#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2025 if(is)
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
High-level pipeline:
- Entry point: ml_analyze(ml_logger, pcap_in_pipe, out_pipe, devices_json_path, progress_json_path, training_enabled)
- Init:
    * logging, dirs
    * load country resources
    * load user's devices
    * spin worker pool (cpu_count()-1)
    * Assure all ml components are present for all devices
    * Ensure thresholds are up to date for all devices
- Main loop:
    * await PCAP on input pipe
    * parse header-level data + compute stats
    * group packets by device MAC -> {mac: [[packet_header_features...], ...]}
    * for each device in pcap:
        - decide task (skip if training ongoing)
        - dispatch to worker: infer or collect or train
            * infer: calculate features -> forward pass -> anomaly scores -> threshold compare -> heuristic -> device result
            * collect: collect features -> append to dataset -> update training status. Main thread intiates train task if dataset collection is complete.
            * train: load dataset -> train -> compute threshold -> atomically save model+threshold
    * combine: stats + per-device results -> write to out_pipe (JSON)
    * carries over information between tasks:
        - pcap carryover: pcap data for next window
        - previous scores: previous scores for continuous detection
        - training status: training status of the device
- Errors:
    * catch exceptions per pcap; write structured error to out_pipe
- Files:
    * logs       → /shared/logs/ml_analyze.log
    * datasets   → /shared/ml/datasets/{mac-dashed}}.csv.gz}
    * models     → /shared/ml/models/{mac-dashed}.pt
    * thresholds → /shared/ml/anomaly_thresholds.json
    * 
"""

from __future__ import annotations

import os
import json
import time
import uuid
import glob
import math
import ipaddress
import dpkt
import shutil
import signal
import logging
import hashlib
import traceback
from logging.handlers import TimedRotatingFileHandler
import argparse
import struct
import bisect
import socket
import base64
import numpy as np
import gzip
import io
import csv
import random
from datetime import datetime, timezone
from functools import lru_cache # check if necessary
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional, Literal, Set
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, Future, as_completed
from multiprocessing import cpu_count, get_context
import pandas as pd

from states import set_state, ERROR

########################################
# 0a) Setup: Constants & Paths
########################################

ROOT_SHARED = Path("/shared/ml")

# This activates some functionalities such as plotting and resetting globals for non-docker execution.
TEST_MODE = False

########################################
# 0b) Setup: Logging
########################################

LOG_DIRECTORY = "/shared/logs"
LOG_FILENAME = "ml_analysis.log"

LOGGING_LEVEL = logging.INFO

logger = None

def _setup_logging() -> None:
    """
    Main-process logging:
    - daily rotation, keep 7 files
    - console INFO, file DEBUG
    - same format as the broader application
    """
    os.makedirs(LOG_DIRECTORY, exist_ok=True)
    log_path = os.path.join(LOG_DIRECTORY, LOG_FILENAME)

    # Optional: clean up prior rotated siblings to start fresh (matches broader logic)
    for old_log in glob.glob(f"{log_path}.*"):
        try:
            os.remove(old_log)
        except OSError:
            pass  # ignore if another process touched it

    fmt = "%(asctime)s %(levelname)-8s %(funcName)-30s %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt=datefmt)

    # Build logger
    global logger
    logger = logging.getLogger(__name__)  # aligns with the broader style
    logger.propagate = False
    logger.setLevel(LOGGING_LEVEL)

    # Avoid duplicate handlers if _setup_logging() is called twice
    logger.handlers.clear()

    fh = TimedRotatingFileHandler(
        filename=log_path,
        when="D",
        interval=1,
        backupCount=7,
        encoding="utf-8",
        delay=False,
        utc=False,  # keep local timestamps in the log lines
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    sh = logging.StreamHandler()
    sh.setLevel(LOGGING_LEVEL)
    sh.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger

def make_inmemory_logger(name: str):
    """
    Returns (logger, stream). Use logger.* in worker;
    call stream.getvalue() at the end to get the full log text.
    """
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(LOGGING_LEVEL)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    # Create an isolated logger (no propagation to root in worker)
    logger = logging.getLogger(name)
    logger.handlers = []          # ensure clean (important if reused in pools/tests)
    logger.propagate = False
    logger.setLevel(LOGGING_LEVEL)
    logger.addHandler(handler)
    return logger, stream

########################################
# 0c) Setup: Country loading
########################################

COUNTRY_RECOGNITION_CSV_FILE = "/config/ip_to_country.csv"

ip_to_country_ranges: List[Tuple[int, int, str]] = []

def load_country_recognition():
    global ip_to_country_ranges
    ip_to_country_ranges.clear()
    with open(COUNTRY_RECOGNITION_CSV_FILE, 'r', newline='') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            start_int = int(row[0].strip())
            end_int = int(row[1].strip())
            country = row[2].strip()
            # Unknown countries for ips are shown as '-'
            if '-' in country:
                country = "Unknown" # Use instead
            ip_to_country_ranges.append((start_int, end_int, country))

########################################
# 0d) Setup: Devices & Progress
########################################

MODEL_DIRECTORY = ROOT_SHARED / "models"

BASE_MODEL_PATH = "/config/base_model.pt"

def get_model_path(mac_key: str) -> str:
    return str(MODEL_DIRECTORY) + f"/{mac_key}.pt"

def adapter_mac_to_script_format(mac_str: str) -> str:
    # Convert to script format (remove colons and convert to lowercase)
    lower_mac_str = mac_str.lower()
    hyphen_formatted_mac = lower_mac_str.replace(":", "-")
    return hyphen_formatted_mac

def script_mac_to_adapter_format(mac_str: str) -> str:
    # Convert to adapter format (add colons and convert to uppercase)
    upper_mac_str = mac_str.upper()
    colon_formatted_mac = upper_mac_str.replace("-", ":")
    return colon_formatted_mac

def load_user_devices(devices_json_path: str) -> set[str]:
    """
    Returns a set of MAC keys (normalized string form)
    Input JSON can be a dict or list with MAC addresses or objects.
    File must exist and be non-empty.
    """
    assert os.path.exists(devices_json_path), f"Devices JSON file {devices_json_path} does not exist"

    devices = set()
    with open(devices_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

        for mac_str in data.keys():
            mac_str = adapter_mac_to_script_format(mac_str)
            devices.add(mac_str)

    logger.info("Loaded %d devices.", len(devices))
    return devices

def reset_device_components(mac_key: str, progress_json_path: str) -> None:
    """
    Resets all machine learning components for a given device MAC key.

    This is used to reset a device to its initial state, which is:
    - A model file is present for the device with the same content as the base model
    - A threshold entry is present for the device with the default threshold.
    - A training status entry is present for the device with an empty training status.
    - The dataset is cleared.
    """

    # Reset model to base model
    model_path = get_model_path(mac_key)
    if os.path.exists(model_path):
        os.remove(model_path)
    shutil.copy(BASE_MODEL_PATH, model_path)

    # Reset threshold to default
    update_threshold(mac_key, DEFAULT_THRESHOLD)

    # Reset training status to empty
    update_device_training_status(progress_json_path, mac_key, new_empty_training_status())

    # Reset dataset
    clear_dataset(mac_key)
    create_new_empty_dataset(mac_key)

def ensure_ml_components_for_devices(devices: set[str], progress_json_path: str) -> None:
    """
    Ensures that all necessary machine learning artifacts exist for each device MAC key:
      - A model file is present for each device (copied from the base model if missing).
      - Each device has an entry in the thresholds mapping (with a default threshold if missing).
      - Each device has an entry in the training progress/status mapping (initialized if missing).
    If changes are made (e.g., thresholds or progress initialized), the respective files are updated.

    Args:
        devices: Set of string MAC keys (normalized form).
        progress_json_path: Path to the JSON status file to track training progress.
    """
    maybe_create_threshold_file()

    # Loads the trainign statuses but also validates them 
    # This makes sure every device that has already been seen before has consistent components
    current_progress = load_and_validate_training_status_json(progress_json_path) 

    # Ensures that the thresholds file is not outdated and recalculates thresholds if necessary
    ensure_thresholds(progress_json_path)

    progress_changed = False
    thresholds_changed = False

    # Go over each device and verify if it already exists via the training status.
    # If the device has no training status, it is considered new and initialized with all new components.
    for mac_key in devices:

        if mac_key not in current_progress:
            # Device is new, initialize with all new components
            logger.info(f"Device {mac_key} is new, initializing with all new components")
            reset_device_components(mac_key, progress_json_path)
        
########################################
# 1a) Thresholds and Anomaly Detection Logic
########################################

THRESHOLD_FILENAME = ROOT_SHARED / "anomaly_thresholds.json"
CURRENT_THRESHOLD_VERSION = "0.9"

DEFAULT_THRESHOLD = 0.0001
DETECT_LOOKBACK_HISTORY_SIZE = 15 # number of previous windows which are considered for the anomaly detection heuristic

# Helper functions for threshold computation

def clean_scores(scores: np.ndarray) -> np.ndarray:
    """
    Remove high value outliers by trimming.
    Removes the highest 1% of scores (according to length) and 
    the highest value from s as long as it is bigger than the previous score * 1.1
    """

    s = np.asarray(scores, dtype=float)
    s = np.sort(s) # ascending order (low to high)

    # Remove the highest 1% of scores (according to length)
    n = s.size
    cutoff = int(np.ceil(n * 0.99))
    s = s[:cutoff]

    # Remove the highest value from s as long as it is bigger than the previous score * 1.1
    # Only allow removal of at most 1% (already trimmed above) in the while loop
    max_remove = max(1, int(np.floor(n * 0.01)))
    removed = 0
    while s[-1] > s[-2] * 1.1:
        if removed >= max_remove:
            break
        s = s[:-1]
        removed += 1

    return s

def _kde_pdf_on_grid(s, grid, bw_factor=1.0):
    """
    Manual implementation so we dont need scipy.
    """
    s = np.asarray(s)
    grid = np.asarray(grid)

    # Silverman’s rule of thumb for bandwidth (same as SciPy default)
    n = len(s)
    std = np.std(s, ddof=1)
    bw = (n * 3.0 / 4.0) ** (-1 / 5) * std * bw_factor

    # Compute Gaussian kernel density estimate manually
    diff = (grid[:, None] - s[None, :]) / bw
    pdf = np.exp(-0.5 * diff**2).sum(axis=1)
    pdf /= (n * bw * np.sqrt(2 * np.pi))
    return pdf

def _kde_at_points(s, pts, bw_factor=1.0):
    # reuse grid-based fallback by local interpolation around each point
    # build a modest grid spanning data
    lo, hi = float(np.min(s)), float(np.max(s))
    if hi <= lo + 1e-12:
        return np.full_like(pts, fill_value=1.0, dtype=float)
    grid = np.linspace(lo, hi, 2048)
    pdf = _kde_pdf_on_grid(s, grid, bw_factor=bw_factor)
    return np.interp(pts, grid, pdf)

# Threshold definitions

# Searches for areas of high densities, best for most scenarios
def density_region_threshold(s: np.ndarray,
                          alpha: float = 0.01,         # keep 99.5% mass
                          bw_factor: float = 0.9,       # KDE bandwidth scale
                          min_cluster_mass: float = 0.05, # keep dense intervals >= 2% mass
                          grid_size: int = 4096,
                          clip_to_01: bool = True) -> float:
    """
    Highest-Density-Region (HDR) threshold for 1D anomaly scores in [0,1].

    Steps:
    1) KDE on a fine grid.
    2) Choose density level λ* so that the superlevel set {x: pdf(x) >= λ*} has total mass ≈ (1 - alpha).
    3) Keep only intervals with mass >= min_cluster_mass (drops tiny specks).
    4) Threshold = rightmost endpoint of the union of kept dense intervals.

    This preserves multiple 'typical' streams if they are truly dense and regular,
    while excluding sparse high-value tails.
    """
    lo, hi = (0.0, 1.0) if clip_to_01 else (float(np.min(s)), float(np.max(s)))
    if hi <= lo + 1e-12:
        return float(hi)

    grid = np.linspace(lo, hi, grid_size)
    pdf = _kde_pdf_on_grid(s, grid, bw_factor=bw_factor)
    pdf = np.maximum(pdf, 0.0)
    dx = grid[1] - grid[0]

    # Normalize pdf to integrate to 1 (numerical)
    Z = np.sum(pdf) * dx
    if Z <= 0:
        return float(np.quantile(s, 1.0 - alpha))  # fallback
    pdf /= Z

    # Find λ* s.t. superlevel mass ≈ (1 - alpha)
    # We do a fast search over unique density values.
    order = np.argsort(-pdf)
    pdf_sorted = pdf[order]
    mass_cum = np.cumsum(pdf_sorted) * dx
    target_mass = 1.0 - alpha
    k = np.searchsorted(mass_cum, target_mass, side='left')
    k = np.clip(k, 0, len(pdf_sorted)-1)
    lam = pdf_sorted[k]

    # Build superlevel mask and identify dense intervals
    mask = pdf >= lam
    # Find contiguous True segments
    edges = np.diff(mask.astype(int))
    starts = np.where(edges == 1)[0] + 1
    ends   = np.where(edges == -1)[0] + 1
    if mask[0]:
        starts = np.r_[0, starts]
    if mask[-1]:
        ends = np.r_[ends, len(mask)]

    # Keep only intervals with enough mass
    kept_right_edges = []
    for a, b in zip(starts, ends):
        interval_mass = np.sum(pdf[a:b]) * dx
        if interval_mass >= min_cluster_mass:
            kept_right_edges.append(grid[b-1])

    if not kept_right_edges:
        # If everything got filtered as tiny, fall back to the biggest mass interval
        if len(starts) > 0:
            masses = [np.sum(pdf[a:b]) * dx for a, b in zip(starts, ends)]
            j = int(np.argmax(masses))
            thr = grid[ends[j]-1]
        else:
            thr = float(np.quantile(s, 1.0 - alpha))
    else:
        thr = max(kept_right_edges)

    return float(np.clip(thr, lo, hi))

# Solid all-round threshold, less robust and often slightly higher than standard
def kde_density_threshold(s: np.ndarray,
                                          bw_factor: float = 1.0,
                                          clip_to_01: bool = True,
                                          min_rank_gap: int = 1,
                                          min_score_gap: float = 0.0):
    """
    Density-only threshold:
      - Sort unique scores s_(1) <= ... <= s_(m).
      - Evaluate KDE f at those points.
      - Find i maximizing a valley score (log-density drop) between s_i and s_{i+1}.
      - Threshold = 0.5 * (s_i + s_{i+1}).

    Params:
      bw_factor     : KDE smoothing multiplier.
      min_rank_gap  : require at least this many raw data points between s_i and s_{i+1}
                      (guards against tiny jitter splits). 1 means no extra guard.
      min_score_gap : minimal absolute gap between s_i and s_{i+1} to consider a split.

    Returns: float threshold.
    """
    s_sorted = np.sort(s)

    # Collapse duplicates but keep multiplicities for rank-gap logic
    vals, idx_start, counts = np.unique(s_sorted, return_index=True, return_counts=True)
    m = len(vals)
    if m == 1:
        return float(vals[0])

    # KDE at the unique values
    f = _kde_at_points(s_sorted, vals, bw_factor=bw_factor)
    f = np.maximum(f, 1e-300)  # numerical safety

    # Precompute cumulative counts to test min_rank_gap between split candidates
    cum_counts = np.cumsum(counts)  # number of points up to each unique value

    # Score each adjacent pair by log-density drop (bigger is sharper valley)
    best_i = None
    best_score = -np.inf
    for i in range(m - 1):
        # rank guard: how many raw samples lie strictly between vals[i] and vals[i+1]?
        between = cum_counts[i]  # up to i inclusive
        # points strictly between = 0 when consecutive unique vals; enforce min_rank_gap via counts on either side if desired
        # We'll approximate by requiring that combined count on either side is at least min_rank_gap+1 apart in rank:
        left_rank_end = cum_counts[i]          # index of last on the left (1..n)
        right_rank_start = cum_counts[i] + 1   # index of first on the right (1..n)
        if (right_rank_start - left_rank_end) < min_rank_gap:
            # too tight by rank constraint (effectively no gap)
            pass  # still evaluate; rank guard mostly relevant when many duplicates
        if (vals[i+1] - vals[i]) < min_score_gap:
            continue

        drop = np.log(f[i]) - np.log(f[i + 1])
        if drop > best_score:
            best_score = drop
            best_i = i

    if best_i is None:
        # fallback: mid between top 2 unique values
        return float(0.5 * (vals[-1] + vals[-2]))

    thr = 0.5 * (vals[best_i] + vals[best_i + 1])
    # ensure within observed range
    lo = 0.0 if clip_to_01 else float(np.min(s))
    hi = 1.0 if clip_to_01 else float(np.max(s))
    return float(np.clip(thr, lo, hi))

# Less stable density based threshold, but for edge cases scenarios sometimes better 
def density_threshold(s: np.ndarray,
                                           bw_factor: float = 1.0,
                                           grid_size: int = 4096,
                                           clip_to_01: bool = True,
                                           min_interval_mass: float = 0.0):
    """
    Density-only threshold:
      - Build KDE f on a grid.
      - Increase density level λ until the superlevel set {x: f(x) ≥ λ} would split.
      - Use the last λ that keeps the set connected; threshold is its right endpoint.
    Optional: 'min_interval_mass' (0 by default) can prune tiny specks that would
    artificially cause an early split.

    Returns: float threshold.
    """
    lo = 0.0 if clip_to_01 else float(np.min(s))
    hi = 1.0 if clip_to_01 else float(np.max(s))
    if hi <= lo + 1e-12:
        return float(hi)

    grid = np.linspace(lo, hi, grid_size)
    pdf = np.maximum(_kde_pdf_on_grid(s, grid, bw_factor=bw_factor), 0.0)
    dx = grid[1] - grid[0]
    Z = np.sum(pdf) * dx
    if Z <= 0:
        # fallback: mid between top 2 unique values if density fails
        uq = np.unique(np.sort(s))
        return float(uq[-1] if uq.size < 2 else 0.5 * (uq[-1] + uq[-2]))
    pdf /= Z

    # If min_interval_mass > 0, we’ll ignore superlevel intervals whose mass < that.
    def connected_intervals(mask):
        edges = np.diff(mask.astype(int))
        starts = np.where(edges == 1)[0] + 1
        ends = np.where(edges == -1)[0] + 1
        if mask[0]:
            starts = np.r_[0, starts]
        if mask[-1]:
            ends = np.r_[ends, len(mask)]
        return starts, ends

    # Sweep candidate lambda values from high to low density
    order = np.argsort(-pdf)
    last_connected_right_edge = grid[-1]
    found_any = False

    for k in range(len(order)):
        lam = pdf[order[k]]
        mask = pdf >= lam
        starts, ends = connected_intervals(mask)

        if min_interval_mass > 0.0:
            # prune tiny intervals
            keep = []
            for a, b in zip(starts, ends):
                mass = np.sum(pdf[a:b]) * dx
                if mass >= min_interval_mass:
                    keep.append((a, b))
            if keep:
                starts = np.array([a for a, _ in keep], dtype=int)
                ends   = np.array([b for _, b in keep], dtype=int)
            else:
                starts = ends = np.array([], dtype=int)

        if len(starts) == 1:
            # still one connected block
            last_connected_right_edge = grid[ends[0] - 1]
            found_any = True
            continue
        else:
            break  # it would split at the next higher λ

    if not found_any:
        # If it split immediately (very bimodal), choose the largest-mass block at the highest λ
        mask = pdf >= pdf[order[0]]
        starts, ends = connected_intervals(mask)
        if len(starts) == 0:
            return float(np.quantile(s, 0.995))
        masses = [np.sum(pdf[a:b]) * dx for a, b in zip(starts, ends)]
        j = int(np.argmax(masses))
        return float(grid[ends[j] - 1])

    return float(np.clip(last_connected_right_edge, lo, hi))

# Regards density areas and distances between scores, vulnerable to heavy outliers
def density_distance_threshold(scores: np.ndarray,
                                   clip_to_01: bool = True,
                                   min_left_mass: float = 0.97,
                                   beta_tail_penalty: float = 0.7,
                                   use_relative_gap: bool = True,
                                   gamma_within_gap: float = 0.7,
                                   leeway_factor: float = 3.0,
                                   min_leeway_abs: float = 0.0,
                                   cap_quantile: float = 99.9):
    """
    Distance-aware, density-free threshold for 1-D anomaly scores.

    Intuition
    ---------
    - Sort scores s_(1) <= ... <= s_(n), compute gaps Δ_i = s_(i+1) - s_(i).
    - Score each potential split i by a 'valley' metric that likes big Δ_i
      and penalizes keeping many points on the right (tail).
    - Choose the split that keeps at least 'min_left_mass' of data on the left.
    - The threshold sits inside the chosen big gap with an offset, and we add a
      LEeway margin for future drift so “almost-bulk” points aren’t flagged.

    Parameters
    ----------
    clip_to_01 : if True, clip scores to [0,1].
    min_left_mass : minimum fraction kept under the threshold (e.g., 0.97 keeps at least 97%).
    beta_tail_penalty : tail penalty exponent; larger => harsher on keeping many right-tail points.
    use_relative_gap : if True, use Δ_i / (s_(i) + eps) to be scale-aware near 0.
    gamma_within_gap : place threshold at s_(i) + gamma * Δ_i (gamma in (0,1)).
    leeway_factor : multiplies local MAD (below the split) to add safety margin.
    min_leeway_abs : absolute minimum leeway added (use a tiny number to always give some headroom).
    cap_quantile : optional safety cap, e.g., 99.9th percentile.

    Returns
    -------
    float
        The threshold.
    """
    # Ttends to be weak to outliers, so clean them first
    s = clean_scores(scores)

    n = s.size
    s_sorted = np.sort(s)

    # Gaps
    gaps = np.diff(s_sorted)
    if not np.any(gaps > 0):
        # All scores equal; give leeway above that point
        base = float(s_sorted[-1])
        # global robust scale ~ MAD
        med = float(np.median(s_sorted))
        mad = float(np.median(np.abs(s_sorted - med))) + 1e-12
        leeway = max(leeway_factor * mad, min_leeway_abs)
        thr = base + leeway
        if clip_to_01:
            thr = min(thr, 1.0)
        # optional cap
        cap = float(np.percentile(s_sorted, cap_quantile))
        return float(min(thr, cap))

    # Evaluate each candidate split i between s_i and s_{i+1}
    # Keep at least 'min_left_mass' on the left
    best_i, best_score = None, -np.inf
    eps = 1e-12
    for i in range(n - 1):
        left_mass = (i + 1) / n
        if left_mass < min_left_mass:
            continue  # would keep too few points under threshold

        right_prop = 1.0 - left_mass  # fraction we put into 'tail'
        gap = gaps[i]

        # Distance term (absolute or relative to scale near zero)
        if use_relative_gap:
            dterm = gap / max(s_sorted[i], eps)
        else:
            dterm = gap

        # Tail penalty: prefer splits that leave fewer right-tail points
        # (if right_prop is tiny, denominator is small -> score gets larger)
        score = dterm / (right_prop + 1e-12) ** beta_tail_penalty

        if score > best_score:
            best_score = score
            best_i = i

    # Fallback if min_left_mass too strict: allow the best overall split
    if best_i is None:
        best_i = int(np.argmax(gaps))
        # also ensure we don't put the cut below almost everything:
        best_i = max(best_i, int(np.ceil(min_left_mass * n)) - 1)

    # Base threshold: inside the chosen big gap
    gap = gaps[best_i]
    base_thr = s_sorted[best_i] + gamma_within_gap * gap

    # Add leeway derived from local scale of the left block (robust)
    left_block = s_sorted[:best_i + 1]
    med_left = float(np.median(left_block))
    mad_left = float(np.median(np.abs(left_block - med_left))) + 1e-12
    leeway = max(leeway_factor * mad_left, min_leeway_abs)

    leeway = min(leeway, base_thr * 0.1) # make sure leeway is not too large

    thr = base_thr + leeway

    # Safety cap against weird tails
    cap = float(np.percentile(s_sorted, cap_quantile))
    thr = min(thr, cap)

    # Clip to bounds
    if clip_to_01:
        thr = float(np.clip(thr, 0.0, 1.0))
    return float(thr)

# Skew-aware robust threshold for one-sided (right-tail) anomaly scores in [0,1].
# Sticks very close to stream, not capturing any outliers, currently not used
def skew_aware_threshold(s: np.ndarray,
                             cap_quantile: float = 99.9,
                             clip_to_01: bool = True) -> float:
    """
    Skew-aware robust threshold for one-sided (right-tail) anomaly scores in [0,1].

    Upper fence = Q3 + 1.5 * exp(3*MC) * IQR           (Hubert–Vandervieren)
    If medcouple MC is unavailable, falls back to Tukey (MC=0).
    Then cap by the 'cap_quantile' to avoid overshoot on tiny samples.
    """
    # ensure numeric finite and within [0,1] if that’s your scale
    s = s[np.isfinite(s)]
    if s.size == 0:
        return 1.0
    if clip_to_01:
        s = np.clip(s, 0.0, 1.0)

    Q1, Q2, Q3 = np.percentile(s, [25, 50, 75])
    IQR = max(Q3 - Q1, 1e-12)

    # Fall back to 0 since we don't have statsmodels.
    MC = 0.0

    # Adjusted upper fence for right-skew (Hubert–Vandervieren 2008)
    upper_fence = Q3 + 1.5 * np.exp(3.0 * MC) * IQR

    # Cap by a high quantile to guard against pathological shapes / tiny n
    cap = float(np.percentile(s, cap_quantile))
    thr = min(upper_fence, cap)

    # Never below Q3 (keeps the main bulk below the threshold)
    thr = max(thr, Q3)

    # Final clip
    return float(np.clip(thr, 0.0, 1.0) if clip_to_01 else thr)

THRESHOLD_FUNCTIONS = [density_region_threshold, kde_density_threshold, density_threshold, density_distance_threshold]

def needle_tail_override(s,
                         base_threshold,
                         logger: logging.Logger,
                         # trigger (needle-tail) detection
                         ratio_p95_med=50.0,          # p95 > 50 * median
                         tail_compact_frac=0.4,        # (max - p95) < 0.4 * (p95 - median)
                         # hybrid guardrails
                         k_mad=6.0,                    # lower guardrail: median + k*MAD
                         p90_lift=0.10,                # add 10% of (p95 - p90) above p90 (small cushion)
                         p95_margin_frac=0.10,         # keep at least 10% gap below p95
                        ):
    """
    If a 'needle tail' is detected (bulk near 0 with tiny, compact high tail),
    override the base threshold with a hybrid:
        thr = clamp(max(median + k*MAD, p90_adj), low=None, high=p95_cap)
    Otherwise, return base_threshold unchanged.
    """

    med = float(np.median(s))
    mad = float(np.median(np.abs(s - med))) + 1e-12
    p90 = float(np.percentile(s, 90))
    p95 = float(np.percentile(s, 95))
    p99 = float(np.percentile(s, 99))
    smax = float(np.max(s))

    # --- detect "needle tail": bulk very small, tail very high and compact ---
    cond_ratio = p95 > ratio_p95_med * med
    if not cond_ratio:
        # No needle tail detected, return base threshold
        logger.info(f"No needle tail detected, keeping base threshold {base_threshold}. Conditions: \n{cond_ratio=}: {p95=} > {ratio_p95_med} * {med=} ")#\n{cond_compact=}: ({smax=} - {p95=}) < {tail_compact_frac} * ({p95} - {med})")
        return base_threshold

    logger.info(f"Needle tail detected, base_threshold: {base_threshold}, med: {med}, p90: {p90}, p95: {p95}, p99: {p99}")

    # Needle tail detected, check if base_threshold needs to be overridden
    # Override if base_threshold is closer to p99 than p90
    dist_to_p90 = abs(base_threshold - p90)
    dist_to_p99 = abs(base_threshold - p99)
    if dist_to_p90 < dist_to_p99:
        # Threshold already closer to p90
        logger.info(f"Threshold already closer to p90, keeping base threshold: {base_threshold}")
        return base_threshold

    # lower guard rail: median + k*MAD, but not higher than p90
    lower_guard = min(med + k_mad * mad, p90)
    # tiny cushion above p90, but still anchored near the bulk edge
    p90_adj = p90 + p90_lift * max(p95 - p90, 0.0)
    # keep some distance below p95 so we don't sit inside the tiny tail
    p95_cap = p95 - p95_margin_frac * max(p95 - med, 1e-12)

    # combined override
    override = max(lower_guard, p90_adj)
    override = min(override, p95_cap)

    logger.info(f"Needle tail set override: threshold from {base_threshold} to {override}, lower_guard: {lower_guard}, p90_adj: {p90_adj}, p95_cap: {p95_cap}")

    return override

def slow_increment_threshold(s: np.ndarray, threshold: float, logger: logging.Logger, increment_factor: float = 1.2, consume_percentage: float = 0.005) -> float:
    """
    Slow increment threshold until no new scores are covered.
    """
    logger.info(f"Slow incrementing threshold from {threshold}")
    old_thr = threshold
    new_thr = old_thr

    consume_threshold = int(len(s) * consume_percentage)
    scores_consumed = consume_threshold + 1

    while scores_consumed > consume_threshold:
        old_thr = new_thr
        new_thr = old_thr * increment_factor
        num_lower_new_thr = np.sum(s < new_thr)
        num_lower_old_thr = np.sum(s < old_thr)
        scores_consumed = num_lower_new_thr - num_lower_old_thr
        logger.info(f"Slow incremented to {new_thr} from {old_thr}, consumed {scores_consumed} scores")
    
    # Reset the last increment factor
    new_thr = old_thr
    logger.info(f"Reset to final threshold: {new_thr}, did not reach consume threshold of {consume_threshold} scores")

    return new_thr

def compute_threshold(scores: np.ndarray, logger: logging.Logger, depth = 0) -> float:

    # Check if max-depth is reached
    if depth == len(THRESHOLD_FUNCTIONS):
        logger.info(f"Reached max-depth, using simple threshold")
        # Simple threshold slightly above 90th percentile, gated by 99th percentile
        threshold = min((np.percentile(scores, 90) + std(s)) * 1.2, np.percentile(s, 99))

    # Usual case: try next threshold function
    elif depth < len(THRESHOLD_FUNCTIONS):
        logger.info(f"Using threshold {THRESHOLD_FUNCTIONS[depth].__name__}")
        threshold = THRESHOLD_FUNCTIONS[depth](scores)
        # Adjust by 1.2 for safety
        threshold = threshold * 1.2

    else:
        # Somehow has recursed past max-depth, hard return 
        logger.info(f"Reached max-depth, using simple threshold")
        return float(np.percentile(s, 99))

    if threshold == 1.0 or threshold == 0.0 or threshold == 0 or threshold == 1:
        # Try next threshold function
        logger.info(f"Threshold is 1.0, 0.0, 0 or 1, trying next threshold function")
        return compute_threshold(scores, logger, depth + 1)

    # Check if needle tail is detected, and override if needed
    needle_safety_thr = needle_tail_override(scores, threshold, logger=logger)

    # Some conditions on p95 < thresh < p99, not hard enforced:
    p90 = np.percentile(scores, 90)
    p95 = np.percentile(scores, 95)
    p99 = np.percentile(scores, 99)
    median = np.median(scores)
    max_score = np.max(scores)
    std = np.std(scores)

    # Start with the check of too high, so we can still increase later if we set it too high now.
    if needle_safety_thr > p99:

        # If median and p95 are very close, we have a dense stream, threshold was mistakenly set very high.
        if abs(median - p95) < std * 2:
            p99save_thr = max(median + 2 * std, p95)
            logger.info(f"median and p95 are very close to each other, setting threshold to {p99save_thr}")
        # Stream is not dense or enough outliers are quite high.
        # Check for big tails
        else:
            # Count scores above p95 and p99
            tail_mass_p95 = np.mean(scores > p95)
            tail_mass_p99 = np.mean(scores > p99)

            # If almost no data lives in upper tail, clamp to p95 to avoid mistakenly high threshold
            if tail_mass_p95 < 0.01 and tail_mass_p99 < 0.005:
                p99save_thr = p95
                logger.info(f"tiny tail above p95/p99, clamping threshold to p95 = {p99save_thr}")
            else:
                # there *is* a real benign high shoulder, keep threshold as is
                logger.info(f"there is a real benign high shoulder, keeping threshold at {needle_safety_thr}")
                p99save_thr = needle_safety_thr

    else:
        # Threshold is below p99, keep as is
        logger.info(f"threshold is below p99, keeping threshold at {needle_safety_thr}")
        p99save_thr = needle_safety_thr

    # Threshold should be above p95, unless p95 is way too high (many high outliers)
    if p99save_thr < p95:
        # Check if threshold is much closer (times 5) to median than to p95
        # Then, it is okay to leave it below p95, otherwise elevate it
        dist_to_median = abs(p99save_thr - np.median(scores))
        dist_to_p95 = abs(p99save_thr - p95)
        if not (dist_to_p95 * 5 > dist_to_median):
            logger.info(f"threshold below p95 and dist_to_p95 * 5 <= dist_to_median, slow incrementing from {p95}")
            p95save_thr = slow_increment_threshold(scores, p95, logger=logger, increment_factor=1.1)
        else:
            logger.info(f"threshold < p95 but p95 far away, slow incrementing from {p99save_thr}")
            p95save_thr = slow_increment_threshold(scores, p99save_thr, logger=logger, increment_factor=1.1)
    # Threshold is above p95, this is the usual case
    else:
        logger.info(f"threshold already above p95, keeping threshold at {p99save_thr}")
        p95save_thr = p99save_thr

    # Check if median and p95 are very close to each other (usually constant stream close to 0)
    if abs(median - p95) < std * 2:
        logger.info(f"median and p95 are very close to each other, checking p99")
        # If also close to p99, treat as flat distribution
        if abs(p95 - p99) < std * 2:
            logger.info(f"p95 and p99 are very close to each other, checking max_score")
            # If max_score is extremely close, just set to max_score
            if abs(max_score - p99) < std:
                logger.info(f"max_score is extremely close to p99, setting threshold to max_score")
                safety_thr = max_score
            # If max_score is not close, slow increment until no new scores are covered
            else:
                logger.info(f"max_score is not close to p99, slow incrementing.")
                safety_thr = slow_increment_threshold(scores, p95save_thr, logger=logger)

        # median and p95 are close, but p99 is not close. Slow increment until no new scores are covered
        else:
            logger.info(f"p95 and p99 are not close to each other, slow incrementing.")
            safety_thr = slow_increment_threshold(scores, p95save_thr, logger=logger)
    # Usual case is median and +95 are not close to each other, the threshold should be safe, since we already checked for p95 > safety_thr
    else:
        logger.info(f"median and p95 are not close to each other, keeping threshold at {p95save_thr}")
        safety_thr = p95save_thr

    # Make double sure: Enforce global bounds, at least 90% under it and never above max score
    upper_bound = max_score
    lower_bound = max(p90, np.sort(scores)[int(len(scores) * 0.9)])
    thr = float(np.clip(safety_thr, lower_bound, upper_bound))
    logger.info(f"final gated threshold: {thr}")

    return thr

def apply_threshold_and_heuristic(scores: np.ndarray, threshold: float):
    """
    Lookback window (k previous + current), where k = DETECT_LOOKBACK_HISTORY_SIZE.
    For each index i >= k, compute mean(scores[i-k : i+1]).
    Mark it anomalous if and only if:
      - The current score (scores[i]) > threshold
      - More than one score in the window > threshold (i.e., at least two scores above threshold in window)
      - At least one of these is true:
          * The mean of the window > threshold
          * At least half of the scores in the window are above threshold
    If any are not met, not anomalous.

    Returns (# anomalous scores, mask of anomalies).
    If there are fewer than (k+1) points total, returns (0, mask_of_all_False).    
    """
    s = np.asarray(scores, dtype=float)
    n = s.size
    k = DETECT_LOOKBACK_HISTORY_SIZE

    w = k + 1  # window size = k lookback + current

    # guard for short sequences
    if n < w:
        return 0, np.zeros(n, dtype=bool)

    cumsum = np.cumsum(np.insert(s, 0, 0.0))
    win_sum = cumsum[w:] - cumsum[:-w]
    win_mean = win_sum / w

    idxs = np.arange(k, n)  # index of current score for each window
    win_scores = np.lib.stride_tricks.sliding_window_view(s, w)  # shape: (n-w+1, w)
    count_above_thr = (win_scores > threshold).sum(axis=1)

    # Condition 1: current score > threshold
    c1 = s[idxs] > threshold
    # Condition 2: more than one score in the window > threshold
    c2 = count_above_thr > 3
    # Condition 3ac: mean of window > threshold and at least a third the window above threshold
    c3a = win_mean > threshold 
    c3c = count_above_thr >= (w * 0.34)
    # Condition 3b: at least half the window above threshold
    c3b = count_above_thr >= (w // 2 + (w % 2)) 
    # Final: c1, c2, and either (c3a and c3c or c3b)
    anomaly_bool = c1 & c2 & ((c3a & c3c) | c3b)

    anomalies_idx = idxs[anomaly_bool]
    anomalies_mask = np.zeros_like(s, dtype=bool)
    anomalies_mask[anomalies_idx] = True
    anomalies = int(np.count_nonzero(anomalies_mask))

    return anomalies, anomalies_mask

def load_thresholds() -> Dict[str, float]:
    """
    Load thresholds from JSON file.
    File must exist.
    Returns {} if no thresholds exist.
    """
    with open(THRESHOLD_FILENAME, "r", encoding="utf-8") as f:
        json_content = json.load(f)
    thresholds = {}
    for mac, value in json_content.items():
        thresholds[mac] = value["threshold"]
    return thresholds

def save_thresholds(thresholds: Dict[str, float]) -> None:
    """
    Save thresholds to JSON file.
    """
    with open(THRESHOLD_FILENAME, "r", encoding="utf-8") as f:
        json_content = json.load(f)

    for mac, threshold in thresholds.items():
        json_content[mac] = {"version": CURRENT_THRESHOLD_VERSION, "threshold": threshold}

    with open(THRESHOLD_FILENAME, "w", encoding="utf-8") as f:
        json.dump(json_content, f, ensure_ascii=False, indent=4)

def update_threshold(mac_key: str, threshold: float) -> None:
    """
    Updates the threshold for a given device MAC key.
    Does not matter if the device already has a threshold or not.
    """
    thresholds = load_thresholds()
    thresholds[mac_key] = threshold
    save_thresholds(thresholds)

def maybe_create_threshold_file() -> None:
    """
    Creates the threshold file if it does not exist.
    """
    if not os.path.exists(THRESHOLD_FILENAME):
        logger.warning(f"Threshold file {THRESHOLD_FILENAME} does not exist, should only happen in initial setup.")
        with open(THRESHOLD_FILENAME, "w") as meta_file:
            json.dump({}, meta_file)

    elif os.path.getsize(THRESHOLD_FILENAME) == 0:
        logger.warning(f"Threshold file {THRESHOLD_FILENAME} exists, but is empty, creating proper empty file.")
        with open(THRESHOLD_FILENAME, "w") as meta_file:
            json.dump({}, meta_file)

    # See if the file is in the correct format # TODO: Remove this once the file is in the new format
    else:
        with open(THRESHOLD_FILENAME, "r", encoding="utf-8") as f:
            json_content = json.load(f)

        # File is empty or only contains {}, nothing to do
        if not json_content:
            return

        try:
            version = next(iter(json_content.values()))["version"]
        except Exception:
            logger.warning(f"Threshold file {THRESHOLD_FILENAME} in old format found, updating file.")
            new_thresholds = {}
            for key, threshold in json_content.items():
                new_thresholds[key] = {"version": "0", "threshold": threshold} # Set version to 0 to indicate old format
            with open(THRESHOLD_FILENAME, "w", encoding="utf-8") as f:
                json.dump(new_thresholds, f, ensure_ascii=False, indent=4)

def _compute_threshold_job(mac: str) -> Tuple[str, Optional[float], Optional[str]]:
    try:
        wlogger, buffer = make_inmemory_logger(f"worker:{mac}")
        try:
            full_dataset = load_dataset(mac)
            model = ml_util.load_model(get_model_path(mac))
            scores = ml_util.infer(model, full_dataset)
            threshold = compute_threshold(scores, logger=wlogger)
            return mac, threshold, buffer.getvalue()
        except Exception as e:
            wlogger.exception(f"Error computing threshold for device {mac}: {e}")
            return mac, None, buffer.getvalue()
    except Exception as e:
        return mac, None, f"Failed to create wlogger for device {mac}: {e}"

def ensure_thresholds(training_status_json_path: str) -> None:
    """
    Should only happen in script startup. Requires that the threshold file exists.
    Ideally, should be called after loading the training statuses, otherwise might break or thresholds might be recalculated unnecessarily.
    Validates whether the thresholds are too old, by checking file hash for changes.
    If too old, initiates recomputation of thresholds and saves them.
    """
    with open(THRESHOLD_FILENAME, "r", encoding="utf-8") as f:
        json_content = json.load(f)

    # Iterate through each model to check if the version is the same as the current script hash
    thresholds_updated = False

    current_statuses = _load_training_status_json(training_status_json_path)
    recalculation_tasks = []
    for mac, status in current_statuses.items():
        # Check if threshold exists
        try: 
            threshold_config = json_content[mac]
        except KeyError:
            logger.error(f"Threshold does not exist for device {mac}. Resetting device components.")
            reset_device_components(mac, training_status_json_path)
            continue

        # Check if version is outdated
        if threshold_config["version"] != CURRENT_THRESHOLD_VERSION:
            logger.warning(f"Threshold for device{mac} is outdated.")

            # Training is complete, check version
            if status.progress == 1.0:
                # Check if version is the same as the current script hash
                logger.warning(f"Device{mac} has a trained model, but the threshold is outdated, recalculating threshold.")

                dataset_path = get_dataset_path(mac)
                if not os.path.exists(dataset_path):
                    logger.error(f"Dataset does not exist for device {mac}. Resetting device components.")
                    reset_device_components(mac, training_status_json_path)
                    continue
                
                # Has dataset and model, needs updated threshold, add to tasks
                recalculation_tasks.append(mac)
            # Training is not complete, just update version
            else:
                logger.warning(f"Device {mac} has no trained model, but the threshold is outdated, updating version.")
                json_content[mac] = {"version": CURRENT_THRESHOLD_VERSION, "threshold": threshold_config["threshold"]}
                thresholds_updated = True

    if recalculation_tasks:
        with ProcessPoolExecutor(max_workers=1, initializer=_worker_initializer) as temp_pool:   
            recalculation_futures = list(temp_pool.map(_compute_threshold_job, recalculation_tasks))

        for mac, threshold, logger_result in recalculation_futures:
            if logger_result is not None and len(logger_result) > 0:
                header = f"\nWorker log START device={mac} action=compute_threshold"
                footer = f"Worker log END device={mac} action=compute_threshold"
                logger.info(f"{header}\n{logger_result}\n{footer}")
            else:
                logger.warning(f"No logger result for device {mac} in compute_threshold action")

            if threshold is None:
                logger.error(f"Failed to compute new threshold for device {mac}. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                continue

            json_content[mac] = {"version": CURRENT_THRESHOLD_VERSION, "threshold": threshold}
            thresholds_updated = True

    if thresholds_updated:
        logger.info(f"Thresholds updated for new version {CURRENT_THRESHOLD_VERSION}, saving to file.")
        with open(THRESHOLD_FILENAME, "w", encoding="utf-8") as f:
            json.dump(json_content, f, ensure_ascii=False, indent=4)

########################################
# 1b) Dataset persistence
########################################

DATASET_DIRECTORY = ROOT_SHARED / "datasets"

def get_dataset_path(mac_key: str) -> str:
    return str(DATASET_DIRECTORY) + f"/{mac_key}.csv.gz"

def append_features_to_dataset(mac_key: str, feats: np.ndarray) -> None:
    """
    Append rows to the gzip file as TSV, like the pandas version did
    (no header, no index). Expects feats.shape == (n_rows, n_cols).
    """
    path = get_dataset_path(mac_key)
    # append text: adds a new gzip member
    with gzip.open(path, "at", newline="") as f:
        np.savetxt(f, feats, delimiter="\t", fmt="%.18g")  # default-ish numeric formatting

def create_new_empty_dataset(mac_key: str) -> None:
    path = get_dataset_path(mac_key)
    with gzip.open(path, "wt", newline="") as f:
        # Write nothing; this creates a valid empty gzip stream
        pass
    if not os.path.exists(path):
        raise ValueError(f"Failed to create empty dataset for device {mac_key}")

def load_dataset(mac_key: str) -> np.ndarray:
    """
    Load TSV (no header) from gzip into a NumPy array.
    Should only be called if the dataset exists and is non-empty.
    """
    path = get_dataset_path(mac_key)
    with gzip.open(path, "rt", newline="") as f:
        return np.loadtxt(f, delimiter="\t")

def clear_dataset(mac_key: str) -> bool:
    """
    Clears the dataset for a given device MAC key, if it exists.
    """
    path = get_dataset_path(mac_key)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False

########################################
# 2) PCAP parsing
########################################

@lru_cache(maxsize=10000)
def get_country(ip_int: int) -> str:
    default_country_value = "Unknown"
    if ip_int < 0:
        return default_country_value
    idx = bisect.bisect_right(ip_to_country_ranges, (ip_int, float('inf'), float('inf'))) - 1
    try:
        start_int, end_int, country = ip_to_country_ranges[idx]
        return country if start_int <= ip_int <= end_int else default_country_value
    except Exception:
        #set_state(EXITED)
        logger.exception("Country lookup error for ip_int=%s", ip_int)
        raise

def mac_bytes_to_str(mac_bytes: bytes) -> str:
    return "-".join(f"{b:02x}" for b in mac_bytes)

def ip_bytes_to_str(ip_bytes: bytes) -> str:
    return socket.inet_ntoa(ip_bytes)

def ip_bytes_to_int(ip_bytes: bytes) -> int:
    return struct.unpack("!I", ip_bytes)[0]

MIN_PACKET_COUNT_FOR_ERROR_CHECK = 50
MAX_ERROR_PERCENTAGE = 0.25

def extract_pcap_infos(pcap: dpkt.pcap.Reader, devices: Set[str]) -> Tuple[Dict[str, List[List[float]]], Dict[str, Any]]:
    """
    Extract packet information from a pcap file.
    Single packet processing fails are accepted, but if too many errors occured, the pcap is regarded as faulty and raises.

    Returns:
        - device_packets: Dict[device_mac, List[List[float]]] - per-device the header information of the packets
        - pcap_statistics: Dict[str, Any] - pcap statistics
    """
    start_time = time.time()

    # These account for all packets, used for determing if the pcap is too faulty to process
    error_count = 0
    total_packet_count = 0

    # These only account for valid packets, used for computing the pcap statistics
    packet_count = 0
    pcap_size = 0

    # Initialize with an empty dictionary for each device, so we always have a result for each device
    device_statistics = {mac_str: {"external_ips": {}, "data_volume": {"packet_count": 0, "data_volume_bytes": 0}} for mac_str in devices}
    device_packets = {mac_str: [] for mac_str in devices}

    flow_ids = {}
    flow_counter = 0
    last_ts = None

    # Go over each packet to extract the necessary information
    for packet in pcap:

        total_packet_count += 1

        if total_packet_count >= MIN_PACKET_COUNT_FOR_ERROR_CHECK and error_count / max(total_packet_count, 1) > MAX_ERROR_PERCENTAGE:
            raise ValueError(f"Too many packet errors in pcap: {error_count} errors out of {total_packet_count} packets (>{MAX_ERROR_PERCENTAGE*100}%) -- skipping this pcap.")

        try:
            ts, buf = packet

            # 1. extract packet information for building the feature vector

            # Skip packets that are too small (at least full Ethernet header)
            if len(buf) < 14:
                logger.warning(f"Skipping packet, too small: {buf}")
                error_count += 1
                continue

            # Convert timestamp to int in microseconds
            ts = int(ts* 1000000)

            packet_length = len(buf)

            # Verify timestamps are monotonically increasing
            if last_ts is not None and ts < last_ts:
                logger.warning(f"Skipping packet, timestamps not in order: found {ts} after {last_ts}")
                error_count += 1
                continue

            last_ts = ts

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.Error, ValueError):
                logger.exception(f"Skipping packet, error parsing ethernet header: {buf}")
                error_count += 1
                continue
            
            # Only IPv4
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                logger.warning(f"Skipping packet, not IPv4: {eth.type}")
                error_count += 1
                continue
            
            ip = eth.data  # type: dpkt.ip.IP
            
            # Only TCP or UDP
            if ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                logger.warning(f"Skipping packet, not TCP or UDP: {ip.p}")
                error_count += 1
                continue
            
            # Extract MAC addresses
            src_mac = mac_bytes_to_str(eth.src)
            dst_mac = mac_bytes_to_str(eth.dst)

            # Extract IP addresses
            src_ip = ip_bytes_to_str(ip.src)
            src_ip_int = ip_bytes_to_int(ip.src)
            dst_ip = ip_bytes_to_str(ip.dst)
            dst_ip_int = ip_bytes_to_int(ip.dst)
            
            # Get transport layer (TCP or UDP)
            l4 = ip.data
            is_tcp = ip.p == dpkt.ip.IP_PROTO_TCP

            src_port = l4.sport
            dst_port = l4.dport
            
            # Extract TCP flags for TCP packets, set to 0 for UDP
            tcp_flags = l4.flags if is_tcp else None

            # Create IP address objects
            src_ip_obj = ipaddress.ip_address(src_ip)
            dst_ip_obj = ipaddress.ip_address(dst_ip)

            # Determine IP locality flags
            is_multicast = src_ip_obj.is_multicast or dst_ip_obj.is_multicast
            is_broadcast = src_ip == "255.255.255.255" or dst_ip == "255.255.255.255" or dst_mac == "ff:ff:ff:ff:ff:ff"
            is_outgoing = None

            if src_mac in devices:
                is_global = not dst_ip_obj.is_private
                is_outgoing = True

                flow_tuple = (ip.p, src_ip, dst_ip, src_port, dst_port)

            elif dst_mac in devices:
                is_global = not src_ip_obj.is_private
                is_outgoing = False

                flow_tuple = (ip.p, dst_ip, src_ip, dst_port, src_port)

            else:
                # Skip packets that are not from any user announced device
                logger.info(f"Skipping packet with src_mac: {src_mac} and dst_mac: {dst_mac}, not from any known device {devices}")
                continue

            device_mac = src_mac if is_outgoing else dst_mac

            if is_multicast or is_broadcast:
                is_global = False

            # Skip non-global packets if specified
            # Currenlty local traffic is included. If it isnt in the future, need to make sure the check for packet statistics is still local inclusive
            #if not include_local and not is_global:
                #continue

            # Get or assign a flow ID
            if flow_tuple not in flow_ids:
                flow_counter += 1
                flow_ids[flow_tuple] = flow_counter

            flowid = flow_ids[flow_tuple]

            # Create packet info (order must match COLUMNS)
            packet_info = [
                flowid,
                ts,
                packet_length,
                src_ip_int,
                dst_ip_int,
                src_port,
                dst_port,
                ip.ttl,
                tcp_flags,
                int(is_outgoing) if is_outgoing is not None else None,
                int(is_tcp),
                int(is_global),
                int(is_multicast),
                int(is_broadcast),
            ]

            device_packets[device_mac].append(packet_info)

            # 2. aggregate statistics for device to display in adapter

            external_ip = dst_ip if is_outgoing else src_ip

            country = get_country(dst_ip_int if is_outgoing else src_ip_int) # Requires ip in int format

            single_device_statistics = device_statistics[device_mac]

            if external_ip not in single_device_statistics["external_ips"]:
                single_device_statistics["external_ips"][external_ip] = {"country": country, "data_volume_bytes": 0, "packet_count": 0}
            single_device_statistics["external_ips"][external_ip]["packet_count"] += 1
            single_device_statistics["external_ips"][external_ip]["data_volume_bytes"] += packet_length

            single_device_statistics["data_volume"]["packet_count"] += 1
            single_device_statistics["data_volume"]["data_volume_bytes"] += packet_length

            packet_count += 1
            pcap_size += packet_length

        except Exception as e:
            logger.exception(f"Skipping packet, unknown error processing: {e}")
            error_count += 1
            continue

    formatted_device_statistics = [{"mac": mac, "external_ips": stats["external_ips"], "data_volume": stats["data_volume"]} for mac, stats in device_statistics.items()]

    pcap_statistics = {
        "totalBytes": pcap_size,
        "packets": packet_count,
        "devices": formatted_device_statistics
    }

    if packet_count > 0:
        logger.info(f"\nDone reading in pcap with {packet_count} packets. \n Avg time per packet: {(time.time() - start_time) / packet_count:.6f}s")
    else:
        error_message = f"Pcap read in successfuly, but "
        if error_count > 0:
            error_message += f"no valid packets found in pcap. {error_count} errors occurred."
        else:
            error_message += f"0 packets found in pcap."

        raise ValueError(error_message)

    return device_packets, pcap_statistics

########################################
# 3a) Feature processing: Helpers
########################################

# Time based windows
WINDOW_TIME_SIZE = 60 * 1_000_000 # 60 seconds in microseconds
WINDOW_TIME_STRIDE = 20 * 1_000_000 # 20 seconds in microseconds

CSV_DTYPE = {"flowid": int,
             "packet_timestamp": int, 
             "packet_length": 'int32', 
             "src_ip": int, 
             "dst_ip": int, 
             "src_port": "int32", 
             "dst_port": "int32", 
             "ip_ttl": "int16", 
             "tcp_flags": "UInt8", 
             "is_outgoing": "bool", 
             "is_tcp": "bool", 
             "is_global": "bool", 
             "is_multicast": "bool", 
             "is_broadcast": "bool"
}

@dataclass
class PcapCarryover:
    iat_last_flow_id: Optional[str] = None
    iat_last_global_ts: Optional[int] = None
    flow_change_last_flow_id: Optional[str] = None

def _safe_div(numer: pd.Series, denom: pd.Series) -> pd.Series:
    """
    Divide numer / denom elementwise, but whenever denom == 0 produce 0 instead of inf or NaN.
    """
    result = numer.div(denom)
    # any inf (from x/0) → 0, and any NaN → 0
    return result.replace([np.inf, -np.inf], 0).fillna(0)

def log_cap_scale(s: pd.Series, max_value: float, min_value: float = 0.0) -> pd.Series:
    """
    Compress a positive long-tailed feature into [0, 1] using log1p scaling.
    Parameters:
    s          : pd.Series of numeric values
    max_value  : float
        Upper cap *before shifting*. Values above this will be clipped.
    min_value  : Optional[float]
        If provided, all values are shifted by (x - min_value).
        max_value will also be internally adjusted: (max_value - min_value)

    Returns
    -------
    pd.Series (float32), scaled to [0, 1]
    """
    if min_value != 0.0:
        shift = min_value
        s = s - shift
        effective_cap = max_value - shift
    else:
        effective_cap = max_value

    capped = s.clip(lower=0, upper=effective_cap)
    return (np.log1p(capped) / np.log1p(effective_cap)).astype("float32")

def balance05(a: pd.Series, b: pd.Series, eps: float = 0.01) -> pd.Series:
    """
    Symmetric log ratio mapped to [0, 1] with 0.5 = balance.

    balance05  = 0.5 * (1 + tanh( log1p(a+eps) - log1p(b+eps) ))

    Works for counts/bytes where a or b can be zero.

    Parameters
    ----------
    a, b : pd.Series of non-negative values
    eps  : float
        Added to avoid log1p(0).  Defaults to 1.0 for count/byte scales.

    Returns
    -------
    pd.Series (float32) in [0, 1]
    """
    return (0.5 * (1.0 + np.tanh(np.log1p(a + eps) - np.log1p(b + eps)))).astype(
        "float32"
    )

def normalize(s: pd.Series, min: int, max: int) -> pd.Series:
    """
    Map a feature onto [0, 1].

    Parameters
    ----------
    s : pd.Series of uint8 / int8
    min : int
    max : int

    Returns
    -------
    pd.Series (float32)
    """
    return (s.astype("float32") / (max - min)).clip(0.0, 1.0)

########################################
# 3b) Feature processing: Feature definitions
########################################

"""
current_script_features = [
 'packet_count_scaled', 
 'out_pkts_scaled', 
 'in_pkts_scaled', 
 'packets_per_second_scaled', 
 'total_bytes_scaled', 
 'out_bytes_scaled', 
 'in_bytes_scaled', 
 'bytes_per_second_scaled', 
 'byte_balance05', 
 'flow_count_scaled', 
 'src_ip_count_scaled', 
 'dst_ip_count_scaled', 
 'connection_count_scaled', 
 'flow_change_mean', 
 'iat_scaled_min', 
 'iat_scaled_max', 
 'iat_scaled_median', 
 'iat_scaled_mean', 
 'payload_len_scaled_min', 
 'payload_len_scaled_max', 
 'payload_len_scaled_median', 
 'payload_len_scaled_mean', 
 'src_port_system_mean', 
 'src_port_user_mean', 
 'src_port_dynamic_mean', 
 'dst_port_system_mean', 
 'dst_port_user_mean', 
 'dst_port_dynamic_mean', 
 'ip_ttl_norm_min', 
 'ip_ttl_norm_max', 
 'ip_ttl_norm_median', 
 'ip_ttl_norm_mean', 
 'tcp_flag_cwr_mean', 
 'tcp_flag_ece_mean', 
 'tcp_flag_urg_mean', 
 'tcp_flag_ack_mean', 
 'tcp_flag_psh_mean', 
 'tcp_flag_rst_mean', 
 'tcp_flag_syn_mean', 
 'tcp_flag_fin_mean', 
 'is_outgoing_mean', 
 'is_tcp_mean', 
 'is_global_mean', 
 'is_multicast_mean', 
 'is_broadcast_mean']
"""

def process_native_features(grouped: pd.core.groupby.DataFrameGroupBy) -> pd.DataFrame:
    """
    """
    # These are prerequisited for multiple features
    duration_us = grouped["packet_timestamp"].max() - grouped["packet_timestamp"].min() # in microseconds
    duration_s = duration_us.div(1_000_000) # in seconds

    # Packet count prerequisits
    packet_count = grouped.size()
    out_pkts = grouped["is_outgoing"].sum()
    in_pkts = packet_count - out_pkts
    
    # Byte count prerequisits
    tot_bytes = grouped["packet_length"].sum()
    out_bytes = grouped.apply(lambda df: df.loc[df["is_outgoing"], "packet_length"].sum()) # TODO: supress warning
    in_bytes = tot_bytes - out_bytes

    # We collect all requested features in a dictionary, to return them at the end
    output_data: Dict[str, pd.DataFrame] = {}
    # Only compute those features that have been requested

    # Packet count features
    output_data["packet_count_scaled"] = log_cap_scale(packet_count, max_value=32)
    output_data["out_pkts_scaled"] = log_cap_scale(out_pkts, max_value=32)
    output_data["in_pkts_scaled"] = log_cap_scale(in_pkts, max_value=32)
    output_data["packets_per_second_scaled"] = log_cap_scale(_safe_div(packet_count, duration_s), max_value=10_000)

    # Byte count features
    output_data["total_bytes_scaled"] = log_cap_scale(tot_bytes, max_value=1_500)
    output_data["out_bytes_scaled"] = log_cap_scale(out_bytes, max_value=1_500)
    output_data["in_bytes_scaled"] = log_cap_scale(in_bytes, max_value=1_500)
    output_data["bytes_per_second_scaled"] = log_cap_scale(_safe_div(tot_bytes, duration_s), max_value=10_000_000)
    output_data["byte_balance05"] = balance05(out_bytes, in_bytes)

    # Avoid division by zero for window specific features
    is_single_packet_window = packet_count == 1
    safe_packet_count = packet_count.copy()
    safe_packet_count.loc[is_single_packet_window] = 2.0

    safe_flow_count = grouped["flowid"].nunique().copy()
    safe_flow_count.loc[is_single_packet_window] = 2.0

    safe_src_ip_count = grouped["src_ip"].nunique().copy()
    safe_src_ip_count.loc[is_single_packet_window] = 2.0

    safe_dst_ip_count = grouped["dst_ip"].nunique().copy()
    safe_dst_ip_count.loc[is_single_packet_window] = 2.0

    safe_connection_count = grouped.apply(
        lambda df: pd.Series(
            [tuple(sorted([src, dst])) for src, dst in zip(df["src_ip"], df["dst_ip"])]
        ).nunique()
    ).copy()
    safe_connection_count.loc[is_single_packet_window] = 2.0

    output_data["flow_count_scaled"] = log_cap_scale(safe_flow_count, safe_packet_count, min_value=1)
    output_data["src_ip_count_scaled"] = log_cap_scale(safe_src_ip_count, safe_packet_count, min_value=1)
    output_data["dst_ip_count_scaled"] = log_cap_scale(safe_dst_ip_count, safe_packet_count, min_value=1)
    output_data["connection_count_scaled"] = log_cap_scale(safe_connection_count,safe_packet_count, min_value=1)

    return pd.DataFrame(output_data)

def process_packet_features(packets: pd.DataFrame, device_carryover: PcapCarryover) -> Tuple[pd.DataFrame, PcapCarryover]:
    """
    """
    output_data: dict[str, pd.Series | int] = {}

    #########################################################
    # FLOW CHANGE FEATURE
    #########################################################

    flowids = packets["flowid"]
    flow_change = (flowids != flowids.shift(1)).astype("int8")
    # Now fix the first row in this chunk by comparing to carry.last_flow_id
    idx0 = flowids.index[0]
    first_flowid = flowids.iat[0]
    if device_carryover.flow_change_last_flow_id is not None and first_flowid == device_carryover.flow_change_last_flow_id:
        # Same flow as last chunk → no change
        flow_change.at[idx0] = 0
    else:
        # Either no carry or different flow → mark new flow
        flow_change.at[idx0] = 1

    # Update carry so next chunk’s first row can compare correctly
    device_carryover.flow_change_last_flow_id = flowids.iat[-1]

    output_data["flow_change"] = flow_change

    #########################################################
    # IAT FEATURE
    #########################################################
    
    # Global IAT with 0 for the first packet
    iat_us = packets["packet_timestamp"].diff().astype("float32") 
    # Set IAT correctly for first packet using carryover state. 
    # If carry.last_global_ts is set, compute the “true” delta for index 0:
    idx0 = iat_us.index[0]
    if device_carryover.iat_last_global_ts is not None:
        iat_us.at[idx0] = float((packets["packet_timestamp"].iat[0] - device_carryover.iat_last_global_ts))
    else:
        iat_us.at[idx0] = 0

    # Update carry.last_global_ts to the timestamp of the final packet in this chunk
    device_carryover.iat_last_global_ts = int(packets["packet_timestamp"].iat[-1]) 

    output_data["iat_scaled"] = log_cap_scale(iat_us, max_value=3_600_000_000)

    #########################################################
    # PAYLOAD LENGTH FEATURE
    #########################################################
    
    payload_lengths = packets["packet_length"].astype("int32").copy()
    
    tcp_mask = packets["is_tcp"].astype(bool)
    payload_lengths.loc[tcp_mask] -= 54 # 14 bytes of ethernet, 20 bytes of IP, 20 bytes of TCP
    payload_lengths.loc[~tcp_mask] -= 42 # 14 bytes of ethernet, 20 bytes of IP, 8 bytes of UDP

    output_data["payload_len_scaled"] = log_cap_scale(payload_lengths, max_value=65535)

    #########################################################
    # PORT FEATURES
    #########################################################
    
    def port_categories(port_series: pd.Series, prefix: str) -> pd.DataFrame:
        return pd.DataFrame(
            {
                f"{prefix}_port_system": (port_series <= 1023).astype("int8"),
                f"{prefix}_port_user": ((1024 <= port_series) & (port_series <= 49151)).astype("int8"),
                f"{prefix}_port_dynamic": (port_series >= 49152).astype("int8"),
            },
            index=port_series.index,
        )

    # build both src and dst at once
    port_df = pd.concat(
        [
            port_categories(packets["src_port"], "src"),
            port_categories(packets["dst_port"], "dst"),
        ],
        axis=1,
    )

    # assign all at once
    output_data.update({c: port_df[c] for c in port_df.columns})

    #########################################################
    # IP TTL FEATURE
    #########################################################
    output_data["ip_ttl_norm"] = normalize(packets["ip_ttl"].fillna(0), 0, 255)

    #########################################################
    # TCP FEATURES
    #########################################################
    
    is_tcp = packets["is_tcp"].astype("int8")
    output_data["is_tcp"] = is_tcp

    tcp_flag_bits = {
        "tcp_flag_cwr": 0x80,
        "tcp_flag_ece": 0x40,
        "tcp_flag_urg": 0x20,
        "tcp_flag_ack": 0x10,
        "tcp_flag_psh": 0x08,
        "tcp_flag_rst": 0x04,
        "tcp_flag_syn": 0x02,
        "tcp_flag_fin": 0x01,
    }

    if not tcp_mask.any():
        # No TCP packets — return empty DataFrame with requested columns, filled with zeros
        for name in tcp_flag_bits.keys():
            output_data[name] = 0
    else:
        flags = packets["tcp_flags"].fillna(0).astype("int32")

        for name, bit in tcp_flag_bits.items():
            output_data[name] = (((flags & bit) != 0) & is_tcp).astype("int8")

    #########################################################
    # STATUS FEATURES
    #########################################################

    output_data["is_outgoing"] = packets["is_outgoing"]
    output_data["is_global"] = packets["is_global"]
    output_data["is_multicast"] = packets["is_multicast"]
    output_data["is_broadcast"] = packets["is_broadcast"]

    return pd.DataFrame(output_data), device_carryover

PACKET_STATS = {
    "flow_change": ["mean"],
    "iat_scaled": ["min", "max", "median", "mean"],
    "payload_len_scaled": ["min", "max", "median", "mean"],

    "src_port_system": ["mean"],
    "src_port_user": ["mean"],
    "src_port_dynamic": ["mean"],
    "dst_port_system": ["mean"],
    "dst_port_user": ["mean"],
    "dst_port_dynamic": ["mean"],

    "ip_ttl_norm": ["min", "max", "median", "mean"],

    "tcp_flag_cwr": ["mean"],
    "tcp_flag_ece": ["mean"],
    "tcp_flag_urg": ["mean"],
    "tcp_flag_ack": ["mean"],
    "tcp_flag_psh": ["mean"],
    "tcp_flag_rst": ["mean"],
    "tcp_flag_syn": ["mean"],
    "tcp_flag_fin": ["mean"],

    "is_outgoing": ["mean"],
    "is_tcp": ["mean"],
    "is_global": ["mean"],
    "is_multicast": ["mean"],
    "is_broadcast": ["mean"]
}

def process_window_features(window_packets: pd.DataFrame, device_carryover: PcapCarryover) -> Tuple[pd.DataFrame, PcapCarryover]:

    grouped = window_packets.groupby("windowid", as_index=True)
    native_feats = process_native_features(grouped)

    # Next we compute packet-level stats. We group by windowid here, because we want to compute stats for each window.
    packet_feats, new_carryover = process_packet_features(window_packets, device_carryover)

    # Since windowid is not a valid packet feature, we just re‐attach it from the original window_packets
    packet_feats = packet_feats.assign(windowid=window_packets["windowid"].values)

    packet_grp = packet_feats.groupby("windowid", as_index=True)

    packet_stat_feats = packet_grp.agg(PACKET_STATS)
    packet_stat_feats.columns = [f"{col}_{stat}" if stat else col for col, stat in packet_stat_feats.columns] # We rewrite columns to include the stat name, e.g. from "(iat_scaled, mean)", we make "iat_scaled_mean"
 
    all_window_feats = pd.concat([native_feats, packet_stat_feats], axis=1)

    return all_window_feats, new_carryover

########################################
# 3c) Feature processing: Top Level Window Processing
########################################

def build_windows(packets_for_device: List[List[Any]]) -> pd.DataFrame:

    # Convert packets_for_device to DataFrame
    columns = list(CSV_DTYPE.keys())  # ensure correct column order
    packets_to_process = pd.DataFrame(packets_for_device, columns=columns)
    packets_to_process = packets_to_process.astype(CSV_DTYPE)

    #packets_to_process = pd.DataFrame(packets_for_device, dtype=CSV_DTYPE)
    completed_windows = []

    # Time based windows
    ts = packets_to_process["packet_timestamp"].to_numpy()
    max_ts = ts[-1]  # keep original dtype; don't cast to int

    window_start = ts[0]

    # slide windows as long as we have enough data
    while window_start + WINDOW_TIME_SIZE <= max_ts:
        mask = (
            (packets_to_process["packet_timestamp"] >= window_start) &
            (packets_to_process["packet_timestamp"] < window_start + WINDOW_TIME_SIZE)
        )
        win = packets_to_process.loc[mask].copy()
        win["windowid"] = int(window_start)
        completed_windows.append(win)
        window_start += WINDOW_TIME_STRIDE

    if completed_windows:
        return pd.concat(completed_windows, ignore_index=True, axis=0)

    return pd.DataFrame()

# TODO: more optimal version here needs checking 
def build_windows_improved(packets_for_device: List[List[Any]]) -> pd.DataFrame:
    # Assumptions guaranteed by caller:
    # - packets_for_device has >= 1 row
    # - rows are sorted by 'packet_timestamp' ascending

    packets_to_process = pd.DataFrame(packets_for_device, dtype=CSV_DTYPE)

    ts = packets_to_process["packet_timestamp"].to_numpy()
    max_ts = ts[-1]  # keep original dtype; don't cast to int

    window_start = ts[0]

    # We want the final *partial* window → iterate while the *start* is within the data range.
    # Each window is [start, start + WINDOW_TIME_SIZE), right-exclusive.
    window_starts = []
    w = window_start
    while w <= max_ts:
        window_starts.append(w)
        w += WINDOW_TIME_STRIDE

    # Two-pointer sweep to collect indices per window in O(N+W)
    left = 0
    right = 0
    idx_chunks = []
    winid_chunks = []

    for w in window_starts:
        end = w + WINDOW_TIME_SIZE

        # advance left to first ts >= w
        while left < ts.size and ts[left] < w:
            left += 1
        # ensure right >= left
        if right < left:
            right = left
        # advance right to first ts >= end  (right-exclusive)
        while right < ts.size and ts[right] < end:
            right += 1

        if right > left:
            # rows [left, right)
            idx = np.arange(left, right)
            idx_chunks.append(idx)
            # store the window start as the windowid (same as your code)
            winid_chunks.append(np.full(idx.size, w, dtype=ts.dtype))
        # else: empty window -> skip (as desired)

    if not idx_chunks:
        # No packets fell into any window (unlikely given assumptions, but safe)
        return pd.DataFrame()

    all_idx = np.concatenate(idx_chunks)
    all_win = np.concatenate(winid_chunks)

    out = packets_to_process.take(all_idx).copy()
    out["windowid"] = all_win
    return out

def process_feature_vector(packets_for_device: List[List[Any]], device_carryover) -> Tuple[np.ndarray, PcapCarryover]:
    """
    Turn per-device packets into feature vectors.
    """
    windows = build_windows(packets_for_device)
    window_features, new_carryover = process_window_features(windows, device_carryover)

    window_features_np = window_features.to_numpy()

    return window_features_np, new_carryover


########################################
# 4) Training progress bookkeeping
########################################

TRAINING_PROGRESS_DATASET_THRESHOLD = 0.95

MAX_DATASET_SIZE: int = 4400          # stop immediately if reached
TARGET_ACTIVE_HOURS: int = 16         # "enough activity across hours"
MAX_DISTINCT_DAYS: int = 4            # stop after 4 distinct active days
MIN_DATASET_SIZE: int = 1000          # minimum required dataset size to train the model

# ===== Bucket helpers =====
def hour_bucket(ts: int) -> int:
    """Bucket seconds-since-epoch into hours (UTC)."""
    return ts // 3600

def day_bucket(ts: int) -> int:
    """Bucket seconds-since-epoch into days (UTC)."""
    return ts // 86400

# ===== Data model =====
@dataclass
class TrainingStatus:
    # Accumulated activity (as sets of buckets)
    current_size: int = 0
    distinct_hour_buckets: Set[int] = field(default_factory=set)
    distinct_day_buckets: Set[int]  = field(default_factory=set)

    # Outputs
    progress: float = 0.0             # 0.0 .. 1.0
    description: str = "Data collection ongoing"

def training_status_to_dict(ts: TrainingStatus) -> dict:
    """Serialize TrainingStatus to a JSON-friendly dict."""
    return {
        "current_size": ts.current_size,
        "distinct_hour_buckets": sorted(int(b) for b in ts.distinct_hour_buckets),
        "distinct_day_buckets": sorted(int(b) for b in ts.distinct_day_buckets),
        "progress": float(ts.progress),
        "description": ts.description,
    }

def training_status_from_dict(d: dict) -> TrainingStatus:
    """Deserialize TrainingStatus from a dict (tolerant of missing fields)."""
    return TrainingStatus(
        current_size=int(d.get("current_size", 0)),
        distinct_hour_buckets=set(int(x) for x in d.get("distinct_hour_buckets", []) or []),
        distinct_day_buckets=set(int(x) for x in d.get("distinct_day_buckets", []) or []),
        progress=float(d.get("progress", 0.0)),
        description=d.get("description", "Data collection ongoing"),
    )

def new_empty_training_status() -> TrainingStatus:
    """
    Create a baseline TrainingStatus with *no* guessed timestamps.
    Caller will let evaluate() add current hour/day buckets when invoked.
    """
    return TrainingStatus(
        current_size=0,
        distinct_hour_buckets=set(),
        distinct_day_buckets=set(),
        progress=0.0,
        description="Data collection ongoing",
    )

# ===== Core logic =====
def _compute_progress(current_size: int, distinct_hours: int, distinct_days: int) -> float:
    # Progress grows along three tracks; final is the max of them:
    # 1) size track
    size_ratio = min(current_size / MAX_DATASET_SIZE, 1.0)
    # 2) coverage track (needs both >= 2 days and >= TARGET_ACTIVE_HOURS) and minimum dataset size
    coverage_ratio = min(distinct_days / 2.0, 1.0) * min(distinct_hours / TARGET_ACTIVE_HOURS, 1.0) * min(current_size / MIN_DATASET_SIZE, 1.0)
    # 3) active-days track (cap at 4 days) and minimum dataset size
    days_ratio = min(distinct_days / MAX_DISTINCT_DAYS, 1.0) * min(current_size / MIN_DATASET_SIZE, 1.0)

    progress = max(size_ratio, coverage_ratio, days_ratio)
    
    # Training progress grows from 0.0 to TRAINING_PROGRESS_DATASET_THRESHOLD while building the dataset
    # The remaining progress is the progress of the training phase
    dataset_collection_progress = progress * TRAINING_PROGRESS_DATASET_THRESHOLD
    if current_size > 0:
        dataset_collection_progress = max(dataset_collection_progress, 0.01) # Prevent calculated progress from being 0 for small datasets
    dataset_collection_progress = round(dataset_collection_progress, 2)

    return dataset_collection_progress

def evaluate_dataset_collection_complete(training_status: TrainingStatus) -> bool:
    return training_status.progress >= TRAINING_PROGRESS_DATASET_THRESHOLD 

def _describe(distinct_hours: int, distinct_days: int, progress: float) -> str:
    if progress == 1.0:
        return "Training complete"
    if progress >= TRAINING_PROGRESS_DATASET_THRESHOLD:
        return "Training in progress"

    # Problem hints only when progress isn't going well
    if distinct_days == 0:
        return "No activity observed yet"
    # Rare usage: average usage should be ~ 6 hours a day atleast during training
    if distinct_days > 1 and distinct_days * distinct_hours < distinct_days * 6:
        return "Device used too rarely"
    # Produces too little data - below data per hour threshold: max ~ 180 windows per hour, min ~ 30 windows per hour
    if distinct_hours * 30 < MIN_DATASET_SIZE:
        return "Produces too little data"

    # Default case, everything is fine
    return "Data collection ongoing"

def reevaluate_training_status(old_dev_status: TrainingStatus, new_dataset_size: int, training_complete: bool = False) -> TrainingStatus:
    """
    Constructs and returns a NEW TrainingStatus (does not mutate the old one).
    - Adds the *current* hour/day buckets here.
    """
    if training_complete:
        return TrainingStatus(
            current_size=old_dev_status.current_size,
            distinct_hour_buckets=old_dev_status.distinct_hour_buckets,
            distinct_day_buckets=old_dev_status.distinct_day_buckets,
            progress=1.0,
            description="Training complete"
        )
    
    now = int(time.time())

    # Start from old sets, then add the current observation's buckets
    new_hour_buckets = set(old_dev_status.distinct_hour_buckets)
    new_day_buckets  = set(old_dev_status.distinct_day_buckets)
    new_hour_buckets.add(hour_bucket(now))
    new_day_buckets.add(day_bucket(now))

    distinct_hours = len(new_hour_buckets)
    distinct_days  = len(new_day_buckets)

    progress = _compute_progress(
        current_size=new_dataset_size,
        distinct_hours=distinct_hours,
        distinct_days=distinct_days,
    )
    desc = _describe(distinct_hours, distinct_days, progress)

    # Return a fresh immutable object
    return TrainingStatus(
        current_size=new_dataset_size,
        distinct_hour_buckets=new_hour_buckets,
        distinct_day_buckets=new_day_buckets,
        progress=progress,
        description=desc,
    )

# ===== JSON file helpers =====
def _load_training_status_json(training_status_json_path: str) -> Dict[str, TrainingStatus]:
    """
    Load a JSON file mapping { mac: TrainingStatus-as-dict }.
    File must exist.
    Returns {} if file is empty.
    """
    assert os.path.exists(training_status_json_path), f"Training status JSON file {training_status_json_path} does not exist"
    
    if os.path.getsize(training_status_json_path) == 0:
        logger.warning(f"Training status JSON file {training_status_json_path} is empty, should only happen in initial setup")
        return {}
    else:
        with open(training_status_json_path, "r", encoding="utf-8") as f:
            raw = json.load(f)  
        out: Dict[str, TrainingStatus] = {}
        if isinstance(raw, dict):
            for mac, d in raw.items():
                if isinstance(d, dict):
                    out[str(mac)] = training_status_from_dict(d)

    return out

def load_and_validate_training_status_json(training_status_json_path: str) -> Dict[str, TrainingStatus]:
    """
    Load a JSON file mapping { mac: TrainingStatus-as-dict }.
    File must exist.
    Returns {} if file is empty.

    Checks for validity of training statuses and resets them if necessary.
    For this, it checks if device is in training but has no dataset.
    """
    current_statuses = _load_training_status_json(training_status_json_path)

    # Check validity of training statuses
    base_model_hash = hashlib.sha256(open(BASE_MODEL_PATH, "rb").read()).hexdigest()
    thresholds = load_thresholds()

    invalid = False
    for mac, status in current_statuses.items():

        try:
            model_threshold = thresholds[mac]
        except KeyError:
            logger.error(f"No threshold found for device {mac}. Resetting device components.")
            reset_device_components(mac, training_status_json_path)
            invalid = True
            continue

        # Training is complete, non-base model and threshold should exist
        if status.progress == 1.0:

            # Verify model exists and differs from base model
            model_path = get_model_path(mac)
            if not os.path.exists(model_path):
                logger.error(f"Training status is complete for device {mac} but a model does not exist. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                invalid = True
                continue
            else:
                model_hash = hashlib.sha256(open(model_path, "rb").read()).hexdigest()

                if model_hash == base_model_hash:
                    logger.error(f"Training status is complete for device {mac} but model is identical to base model. Resetting device components.")
                    reset_device_components(mac, training_status_json_path)
                    invalid = True
                    continue
            
            # Verify threshold is not the default threshold
            model_threshold = thresholds[mac]
            if model_threshold == DEFAULT_THRESHOLD:
                logger.error(f"Training status is complete for device {mac} but threshold is identical to default threshold. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                invalid = True
                continue

        # Device is currently in training
        if 0.0 < status.progress < 1.0: 

            # Verify dataset size is not 0
            if status.current_size == 0:
                logger.error(f"Training status is in progress for device {mac} but the dataset size is 0. This should not happen. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                invalid = True
                continue

            # Verify dataset exists
            dataset_path = get_dataset_path(mac)
            if not os.path.exists(dataset_path):
                logger.error(f"Training status is in progress for device {mac} but the dataset does not exist. This should not happen. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                invalid = True
                continue

            # Verify dataset is valid
            try:
                dataset = load_dataset(mac)
            except:
                logger.error(f"Training status is in progress for device {mac} but the dataset appears to be corrupted, could not be loaded. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                invalid = True
                continue    

        # Device has not started training yet
        if status.progress == 0.0:

            # Verify dataset size is 0
            if status.current_size != 0:
                logger.error(f"Training has not started for device {mac} but the dataset size is not 0. This should not happen. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                invalid = True
                continue

            # Verify dataset exists
            dataset_path = get_dataset_path(mac)
            if not os.path.exists(dataset_path):
                logger.error(f"Training has not started for device {mac} but the dataset does not exist. This should not happen. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                invalid = True
                continue

            # Verify model exists and equals base model
            model_path = get_model_path(mac)
            if not os.path.exists(model_path):
                logger.error(f"Device {mac} has training status but no model exists. This should not happen. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                invalid = True
                continue
            else:
                model_hash = hashlib.sha256(open(model_path, "rb").read()).hexdigest()
                if model_hash != base_model_hash:
                    logger.error(f"Device {mac} has not trained yet, but the model is not identical to the base model. This should not happen. Resetting device components.")
                    reset_device_components(mac, training_status_json_path)
                    invalid = True
                    continue

            # Verify threshold is the default threshold
            if model_threshold != DEFAULT_THRESHOLD:
                logger.error(f"Training has not started for device {mac} but the threshold is not the default threshold. This should not happen. Resetting device components.")
                reset_device_components(mac, training_status_json_path)
                invalid = True
                continue

    # If we found any invalid statuses, we need to load the statuses again to make sure we dont return the overwritten ones
    if invalid:
        current_statuses = _load_training_status_json(training_status_json_path)
    return current_statuses

def save_training_status_json(path: str, status_map: Dict[str, TrainingStatus]) -> None:
    """
    Save { mac: TrainingStatus } to JSON (atomic-ish write).
    """
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")

    payload = {
        str(mac): training_status_to_dict(ts)
        for mac, ts in status_map.items()
    }

    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    tmp.replace(p)

def update_device_training_status(path: str, mac: str, status: TrainingStatus) -> None:
    """
    Update (or insert) a single device's TrainingStatus in the JSON file.
    Does not matter if the device already has a training status or not.
    """
    mapping = _load_training_status_json(path) 
    mapping[str(mac)] = status
    save_training_status_json(path, mapping)


########################################
# 5a) Worker logic: Task decision
########################################

ACTION_INFER = "INFER"
ACTION_COLLECT = "COLLECT"
ACTION_TRAIN = "TRAIN"

def decide_action_for_device(dev_progress: TrainingStatus, training_enabled: bool) -> Literal[ACTION_INFER, ACTION_COLLECT, ACTION_TRAIN]:
    """
    Logic:
      - if training_enabled:
          * if progress indicates "training_in_progress": skip
          * else:
              - if training is still ongoing (progress < 1.0): train
              - else: infer
      - else: infer
    """
    if not training_enabled:
        if dev_progress.progress != 1.0:
            logger.warning(f"Forcing inference for device {dev_mac} without trained model. Results will be unreliable.")
        return ACTION_INFER

    if dev_progress.progress < 1.0:
        if evaluate_dataset_collection_complete(dev_progress):
            return ACTION_TRAIN
        else:
            return ACTION_COLLECT
    return ACTION_INFER 

########################################
# 5b) Worker logic: task (runs in separate process)
########################################

def maybe_plot(scores_nd: np.ndarray, threshold: float, mac_key: str, anomalies_mask: Optional[np.ndarray] = None) -> None:
    """
    Plots the scores and the threshold, and saves the plot to the shared directory.
    Used for debugging purposes, not used in production.
    """
    import matplotlib.pyplot as plt
    # Make sure scores is 1D
    scores = np.asarray(scores_nd).reshape(-1)

    # X axis = score index starting at 1 (1..N)
    x = np.arange(1, len(scores) + 1)

    # Masks for coloring
    under = scores <= threshold
    over  = scores > threshold

    # Count values relative to threshold
    n_under = np.count_nonzero(under)
    n_over  = np.count_nonzero(over)

    print(f"Worker: {n_over} scores above threshold ({threshold}), {n_under} scores below or equal.")

    # Compute running (rolling) mean and std for each score, using previous `lookback` points (including the current point)
    # If very short series, fall back to global mean/std.
    lookback = DETECT_LOOKBACK_HISTORY_SIZE
    if len(scores) >= 1:
        # Use rolling window up to each score (including current), window size up to lookback
        running_mean = np.array([
            np.mean(scores[max(0, i - lookback + 1):i + 1]) for i in range(len(scores))
        ])
        running_std = np.array([
            np.std(scores[max(0, i - lookback + 1):i + 1]) for i in range(len(scores))
        ])
        # For latest score, use its running mean and std for title
        mean = running_mean[-1]
        std = running_std[-1]
    else:
        running_mean = np.zeros_like(scores)
        running_std = np.zeros_like(scores)
        mean = 0.0
        std = 0.0

    # Create the plot
    fig, ax = plt.subplots(figsize=(10, 4), dpi=120)

    # Scatter points: green under threshold, orange above (smaller dots)
    ax.scatter(x[under], scores[under], s=8, color='green', marker='o', alpha=0.9, edgecolors='none', label='≤ threshold')
    ax.scatter(x[over],  scores[over],  s=8, color='orange', marker='o', alpha=0.9, edgecolors='none', label='> threshold')

    # If anomalies are provided, outline them in red
    if anomalies_mask is not None and np.any(anomalies_mask):
        ax.scatter(
            x[anomalies_mask],
            scores[anomalies_mask],
            s=40, facecolors='none', edgecolors='red', linewidths=1.0, label='anomaly outline'
        )

    # Dotted, thinner blue threshold line
    ax.axhline(y=threshold, linestyle=':', linewidth=2.0, color='blue', label='threshold')


    printer = False
    if mac_key == "ec-da-3b-c6-15-04":
        printer = True

    benign_sorted_scores = np.sort(scores)
    if printer:print(f"mean of benign scores: {np.mean(benign_sorted_scores)}")
    if printer:print(f"max of benign scores: {np.max(benign_sorted_scores)}")
    if printer:print(f"min of benign scores: {np.min(benign_sorted_scores)}")
    if printer:print(f"std of benign scores: {np.std(benign_sorted_scores)}")
    if printer:print(f"median of benign scores: {np.median(benign_sorted_scores)}")

    # Percentile lines - themed as shades of purple
    ninetypercentile = np.percentile(benign_sorted_scores, 90.0)
    if printer:print(f"90%-Line = {ninetypercentile:.4f}")
    # Light brown (hazel/light brown): #bc9b6a
    plt.axhline(ninetypercentile, color='#bc9b6a', linestyle='--', linewidth=0.8, label=f'90% percentile = {ninetypercentile:.4f}')

    ninetyfivepercentile = np.percentile(benign_sorted_scores, 95.0)
    if printer:print(f"95%-Line = {ninetyfivepercentile:.4f}")
    # Hazel brown: #8d6748
    plt.axhline(ninetyfivepercentile, color='#8d6748', linestyle='--', linewidth=0.8, label=f'95% percentile = {ninetyfivepercentile:.4f}')

    ninetyninepercentile = np.percentile(benign_sorted_scores, 99.0)
    if printer:print(f"99%-Line = {ninetyninepercentile:.4f}")
    # Dark red brown: #6b3322
    plt.axhline(ninetyninepercentile, color='#6b3322', linestyle='--', linewidth=0.8, label=f'99% percentile = {ninetyninepercentile:.4f}')

    # Axes & labels
    ax.set_xlabel('Score #')
    ax.set_ylabel('Score')
    ymin = max(0, scores.min() - 0.05)
    ymax = min(1, scores.max() * 1.1)
    ax.set_ylim(ymin, ymax)
    ax.set_xlim(1, len(scores) if len(scores) > 0 else 1)
    ax.set_title(f'Scores vs. Threshold ({len(scores)} points)\nRunning Mean={mean:.3f}, Running Std={std:.3f}')
    ax.legend(frameon=False)

    fig.tight_layout()

    # Save to file
    plot_path = os.path.join(ROOT_SHARED, f"{mac_key}.png")
    fig.savefig(plot_path)
    plt.close(fig)

    print(f"Worker: Saved scores plot to {plot_path}")

@dataclass
class TaskCarryover:
    previous_scores: np.ndarray = field(default_factory=lambda: np.array([]))
    pcap_carryover: PcapCarryover = field(default_factory=PcapCarryover)

def load_task_carryovers(devices: Set[str]) -> Dict[str, TaskCarryover]:
    return {device_mac: TaskCarryover() for device_mac in devices}

@dataclass
class WorkerTask:
    action: Literal[ACTION_INFER, ACTION_COLLECT, ACTION_TRAIN]
    device_mac_key: str
    task_carryover: Optional[TaskCarryover] = None

    # collection / training
    device_status: Optional[TrainingStatus] = None
    # inference / collection
    packet_rows: Optional[List[List[Any]]] = None

@dataclass
class WorkerResult:
    ok: bool
    log: str
    task_carryover: TaskCarryover

    reset: bool = False

    # inference
    anomalies: Optional[List[Dict[str, Any]]] = None
    # collection
    training_status: Optional[TrainingStatus] = None
    # training
    # ?

class CorruptModelError(Exception):
    """Raised when a model checkpoint file is missing, truncated, or invalid."""
    pass

def _worker_initializer():
    # Use this in local testing mode for execution without docker 
    global TEST_MODE
    TEST_MODE = False
    if TEST_MODE:
        global DATASET_DIRECTORY, MODEL_DIRECTORY, THRESHOLD_FILENAME, ROOT_SHARED
        DATASET_DIRECTORY = "placeholder"
        MODEL_DIRECTORY = "placeholder"
        THRESHOLD_FILENAME = "placeholder"
        ROOT_SHARED = Path("placeholder")

    import os, importlib
    os.environ["OMP_NUM_THREADS"] = "1"

    global ml_util
    ml_util = importlib.import_module("ml_util")  # ← binds to module global
    ml_util.set_torch_threads_1()

def _worker_handle_task(task: WorkerTask) -> WorkerResult:
    wlogger, buffer = make_inmemory_logger(f"worker:{task.device_mac_key}")
    try:
        wlogger.info(f"Worker: Starting task action={task.action} for device {task.device_mac_key}")

        result = {"ok": True,"log": f""}

        carryover = task.task_carryover

        if task.action == ACTION_INFER:
            # Feature extraction
            features, pcap_carryover = process_feature_vector(task.packet_rows, carryover.pcap_carryover)
            wlogger.info(f"Worker: Extracted {len(features)} features")

            # Load model and threshold
            model = ml_util.load_model(get_model_path(task.device_mac_key))
            if model is None:
                raise CorruptModelError(f"Worker: Failed to load model {get_model_path(task.device_mac_key)}.")

            threshold = load_thresholds()[task.device_mac_key]
            wlogger.info(f"Worker: Loaded model {get_model_path(task.device_mac_key)} with threshold {threshold}")

            # Infer scores
            scores = ml_util.infer(model, features)  # np.ndarray
            wlogger.info(f"Worker: Did forward pass and got {len(scores)} scores")

            # Load previous scores and prepend (to ensure lookback history for continuous detection)
            previous_scores = carryover.previous_scores
            wlogger.info(f"Worker: Loaded {len(previous_scores)} previous scores")
            scores = np.concatenate([previous_scores, scores])
            if len(scores) < DETECT_LOOKBACK_HISTORY_SIZE + 1:
                wlogger.warning(f"Worker: Not enough scores to apply threshold and heuristic.")

            # Apply threshold and heuristic to return anomalies
            anomalies, anomalies_mask = apply_threshold_and_heuristic(scores, threshold)
            wlogger.info(f"Worker: Applied threshold and heuristic and got {anomalies} anomalies")
            result["anomalies"] = anomalies

            #if TEST_MODE:
            #    maybe_plot(scores, threshold, task.device_mac_key, anomalies_mask)

            # Store the last 5 elements of scores (as np.ndarray) in task_carryover
            carryover.previous_scores = scores[-DETECT_LOOKBACK_HISTORY_SIZE:]
            carryover.pcap_carryover = pcap_carryover

        elif task.action == ACTION_COLLECT:
            # Feature extraction
            features, pcap_carryover = process_feature_vector(task.packet_rows, carryover.pcap_carryover)
            wlogger.info(f"Worker: Extracted {len(features)} features")

            # First 
            current_dataset_size = task.device_status.current_size
            new_dataset_size = current_dataset_size + len(features)
            wlogger.info(f"Worker: Old dataset size was {current_dataset_size}, new dataset size is {new_dataset_size}")

            # Get updated training status, taking new dataset size into consideration
            new_device_status = reevaluate_training_status(task.device_status, new_dataset_size) 
            result["training_status"] = new_device_status
            wlogger.info(f"Worker: Evaluated training status and got {new_device_status}")

            # Append features to dataset
            # If dataset collection is evaluated to be completed, training will be commenced in a separate process (see main loop)
            append_features_to_dataset(task.device_mac_key, features)

            carryover.pcap_carryover = pcap_carryover

        elif task.action == ACTION_TRAIN:
                wlogger.info(f"Worker: Dataset collection is complete, training the model and computing threshold.")
                # Dataset collection is complete, train the model and compute threshold

                full_dataset = load_dataset(task.device_mac_key)
                wlogger.info(f"Worker: Loaded dataset of length {len(full_dataset)}")

                # Load model and train
                model_path = get_model_path(task.device_mac_key)
                model = ml_util.load_model(model_path)
                if model is None:
                    raise CorruptModelError(f"Worker: Failed to load model {model_path}.")
                wlogger.info(f"Worker: Loaded model {model_path}")
                ml_util.finetune(model, full_dataset)
                wlogger.info(f"Worker: Trained model successfully")

                # For the trained model we still need to compute a threshold
                scores = ml_util.infer(model, full_dataset)
                wlogger.info(f"Worker: Did forward pass and got {len(scores)} scores")
                threshold = compute_threshold(scores, logger=wlogger) 
                wlogger.info(f"Worker: Computed threshold and got {threshold}")

                # New training status is complete, with dataset size 0
                new_device_status = reevaluate_training_status(task.device_status, 0, training_complete=True)

                # Update model, threshold and training status
                ml_util.save_model(model, model_path)
                update_threshold(task.device_mac_key, threshold)
                result["training_status"] = new_device_status
                wlogger.info(f"Worker: Saved model and updated threshold. Training status is updated.")

                # Clear the dataset now that model is trained Edit: we do not clear dataset anymore, to enable future threshold recomputation
                #clear_dataset(task.device_mac_key)
                #wlogger.debug(f"Worker: Cleared dataset")

                # Initiate task carryover for upcoming inferences
                carryover.previous_scores = scores[-DETECT_LOOKBACK_HISTORY_SIZE:]

                if TEST_MODE:
                    anomalies, anomalies_mask = apply_threshold_and_heuristic(scores, threshold)
                    maybe_plot(scores, threshold, task.device_mac_key, anomalies_mask)

        else:
            raise ValueError(f"Unknown action: {task.action}")

        wlogger.info(f"Worker: Returning result for device {task.device_mac_key}")
        result["task_carryover"] = carryover
        result["log"] = buffer.getvalue()
        return WorkerResult(**result)

    except CorruptModelError as e:
        wlogger.error(f"Worker task failed: {type(e).__name__}: {e}")
        return WorkerResult(
            ok=False,
            log=buffer.getvalue(),  # include everything logged so far + traceback 
            task_carryover=carryover,
            reset=True,
            )
    except Exception as e:
        wlogger.exception(f"Worker task failed: {type(e).__name__}: {e}")
        return WorkerResult(
            ok=False,
            log=buffer.getvalue(),  # include everything logged so far + traceback 
            task_carryover=carryover,
            )

########################################
# 6) Main analysis loop
########################################

JANNIKLAS_THRESHOLD = 50
JANNIKLAS_THRESHOLD2= 99

def create_device_report(device_mac_key: str, action: Literal[ACTION_INFER, ACTION_COLLECT, ACTION_TRAIN], device_status: TrainingStatus = None, anomalies_found_for_device: int = None, error: str = None) -> Dict[str, Any]:
    report = {}
    report["action"] = action

    if error != None:
        report["error"] = error
        return report

    if action == ACTION_INFER:
        report["num_anomalies"] = anomalies_found_for_device
        if anomalies_found_for_device > 0:
            report["first_occurrence"] = datetime.now(timezone.utc).isoformat() # ISO 8601 format

    elif action == ACTION_COLLECT:
        report["dataset_size"] = device_status.current_size
        report["progress"] = device_status.progress * 100
        report["status_description"] = device_status.description
        report["distinct_hour_buckets"] = list(device_status.distinct_hour_buckets)
        report["distinct_day_buckets"] = list(device_status.distinct_day_buckets)

    elif action == ACTION_TRAIN:
        threshold = load_thresholds()[device_mac_key]
        model_path = get_model_path(device_mac_key)
        report["threshold"] = threshold
        # Read entire model binary, encode with base64 for JSON compatibility
        with open(model_path, "rb") as mf:
            model_bytes = mf.read()
            model_b64 = base64.b64encode(model_bytes).decode('utf-8')
        report["model_base64"] = model_b64
    else:
        raise ValueError(f"Unknown action: {action}")
    return report

def translate_result_to_janniklas(device_report: Dict[str, Any]) -> Dict[str, Any]:
    """
    """
    # Error case
    if "error" in device_report:
        r_type = "Normal"
        description = "Error occured" # device_report["error"] is the error message, but might contain whole worker log, too long?
        randomized_score = 0

    # Normal case
    else:
        action = device_report["action"]
        if action == ACTION_INFER:
            num_anomalies = device_report["num_anomalies"]
            if num_anomalies > 0:
                r_type = "Alert"
                description = f"{num_anomalies} Anomalies detected"
                randomized_score = round(random.uniform(JANNIKLAS_THRESHOLD, JANNIKLAS_THRESHOLD2), 2)
            else:
                r_type = "Normal"
                description = "No Anomalies detected"
                randomized_score = round(random.uniform(0, JANNIKLAS_THRESHOLD - 0.01), 2)
        else:
            r_type = "Normal"
            description = ""
            randomized_score = 0
    
    jan_niklas_report = {
        **device_report,
        "type": r_type,
        "description": description,
        "score": randomized_score
    }

    return jan_niklas_report

def flush_results(out_pipe: str, device_results: Dict[str, Any], pcap_statistics: Dict[str, Any], analysis_ms: int) -> None:
    """
    """
    result_data = {
        "detections": device_results,
        "statistics": {"analysisDurationMs": analysis_ms, **pcap_statistics}, 
    }

    result_text = json.dumps(result_data, indent=4)

    with open(out_pipe, "w") as fw:
        fw.write(result_text)

def flush_error(out_pipe: str, error_msg: str) -> None:
    """
    """
    error_result = {
        "error": error_msg
    }
    error_result_text = json.dumps(error_result, indent=4)
    with open(out_pipe, "w") as fw:
        fw.write(error_result_text)

def assert_enough_packets(packet_rows: List[List[Any]]) -> bool:
    """
    Check if the packet rows have enough packets to build a window.
    Returns:
        - bool: True if enough packets, False otherwise
    """
    first_ts = packet_rows[0][1]
    last_ts = packet_rows[-1][1]
    duration = (last_ts - first_ts)
    return duration > WINDOW_TIME_SIZE
    
def ml_analysis_loop(pcap_in_pipe: str, out_pipe: str, training_enabled: bool, task_carryovers: Dict[str, TaskCarryover], executor: ProcessPoolExecutor, devices: Set[str], progress_json_path: str):
    """
    """
    logger.info(f"Starting ml_analysis_loop")

    # Run forever: wait on pcap pipe
    while True:

        logger.info("Waiting for next pcap on %s ...", pcap_in_pipe)
        # If any unallowed errors occur, the run is considered failed.
        run_failed = False

        try:
            try:
                # Blocking read from pipe to await a new pcap
                with open(pcap_in_pipe, "rb") as fifo:
                    logger.info(f"New pcap from {pcap_in_pipe} received")
                    start_wall = time.time()
                    pcap_reader = dpkt.pcap.Reader(fifo)
                    device_packets, pcap_statistics = extract_pcap_infos(pcap_reader, devices)
                    logger.debug(f"Pcap parsed in {time.time() - start_wall:.6f}s")
            except ValueError as e:
                logger.exception(f"Error reading pcap: {e}")
                raise
            except dpkt.NeedData as e:
                logger.exception(f"NeedData: empty or truncated pcap {e}")
                raise
            except dpkt.UnpackError as e:
                logger.exception(f"Pcap parse error - invalid or corrupted pcap {e}")
                raise
            except Exception as e:
                logger.exception(f"Unknown error parsing pcap: {e}")
                raise

            current_progress = load_and_validate_training_status_json(progress_json_path)

            # Queue futures per device
            future_meta = {}
            futures: List[Future] = []
            device_results: Dict[str, Any] = {}
            logger.debug(f"Queuing tasks for {len(device_packets)} devices")

            train_tasks = []

            for mac_key, packet_rows in device_packets.items():

                if not packet_rows:
                    logger.info(f"No packets found for device {mac_key}, skipping.")
                    continue
                
                if not assert_enough_packets(packet_rows):
                    logger.info(f"Not enough packets found for device {mac_key}, skipping.")
                    continue

                # Decide task
                action = decide_action_for_device(current_progress[mac_key], training_enabled)

                if action == ACTION_TRAIN:
                    # Usually training is triggered immediately after dataset collection is complete, and this should not happen.
                    # However, this might be a leftover from a previous run where an error occured and training was not completed.
                    train_tasks.append(WorkerTask(
                        action=ACTION_TRAIN,
                        device_mac_key=mac_key,
                        device_status=current_progress[mac_key],
                        task_carryover=task_carryovers[mac_key],
                    ))
                    logger.info(f"Found leftover training task for device {mac_key}, queuing it again")
                    continue

                # Dispatch to worker
                try:
                    task = WorkerTask(
                        action=action,
                        device_mac_key=mac_key,
                        packet_rows=packet_rows,
                        device_status=current_progress[mac_key],
                        task_carryover=task_carryovers[mac_key],
                    )

                    fut = executor.submit(_worker_handle_task, task)
                    futures.append(fut)
                    future_meta[fut] = (mac_key, action)
                    logger.info(f"Queued task {action} for device {mac_key}")

                except Exception as e:
                    run_failed = True
                    device_report = create_device_report(mac_key, action, error=f"dispatch failed: {e}")
                    device_results[mac_key] = device_report
                    logger.exception(f"Dispatch failed for device {mac_key} {action} {type(e).__name__}: {e}")

            # Gather results            
            for fut in as_completed(futures):
                mac_key, action = future_meta[fut]
                try:
                    res: WorkerResult = fut.result()
                except Exception as e:
                    run_failed = True
                    device_report = create_device_report(mac_key, action, error=f"worker crashed before returning a result: {e}")
                    device_results[mac_key] = device_report
                    logger.exception(f"Worker with task {action} for device {mac_key} crashed before returning a result: {type(e).__name__}: {e}")
                    continue

                log_text = (res.log or "").rstrip()
                header = f"\n=== Worker log START device={mac_key} action={action} ok={res.ok} ==="
                footer = f"=== Worker log END device={mac_key} ==="

                # Either way, update the task carryover
                task_carryovers[mac_key] = res.task_carryover

                if not res.ok:
                    run_failed = True
                    device_report = create_device_report(mac_key, action, error=log_text)
                    device_results[mac_key] = device_report
                    # Worker log is info if the worker is not successful
                    logger.info("%s\n%s\n%s", header, log_text, footer)

                    if res.reset:
                        logger.error(f"Wroker detected corrupt files for device {mac_key}. Resetting device components.")
                        reset_device_components(mac_key, progress_json_path)
                    continue
                else:
                    # Worker log is debug only if the worker is successful
                    logger.debug("%s\n%s\n%s", header, log_text, footer)
                    if action == ACTION_INFER:
                        anomalies = res.anomalies
                        device_report = create_device_report(mac_key, action, anomalies_found_for_device=anomalies) 
                        device_results[mac_key] = device_report
                        logger.info(f"Found {anomalies} anomalies for device {mac_key}")

                    elif action == ACTION_COLLECT:   
                        # Track training progress for device
                        new_training_status = res.training_status
                        current_progress[mac_key] = new_training_status
                        device_report = create_device_report(mac_key, action, device_status=new_training_status)
                        device_results[mac_key] = device_report
                        update_device_training_status(progress_json_path, mac_key, new_training_status)
                        logger.info(f"Updated progress to {new_training_status} for device {mac_key}")

                        if evaluate_dataset_collection_complete(new_training_status):
                            # If dataset collection is complete, we can train the model
                            logger.info(f"Queuing training task, dataset collection complete for device {mac_key}")
                            train_tasks.append(WorkerTask(
                                action=ACTION_TRAIN,
                                device_mac_key=mac_key,
                                device_status=new_training_status,
                                task_carryover=task_carryovers[mac_key],
                            ))

            if train_tasks:

                with ProcessPoolExecutor(max_workers=1, # Weight changes can mess with multi processing, so a separate pool with 
                 mp_context=get_context("spawn"),    # spawn is the only way to avoid deadlocks. more memory usage though, so only 1 worker
                 initializer=_worker_initializer,       # (technically we could just use the main process, but that would be less clean, and the code exists)
                 ) as train_pool:

                 train_futures = []
                 train_meta = {}
                 for task in train_tasks:
                    train_mac_key = task.device_mac_key
                    fut = train_pool.submit(_worker_handle_task, task)
                    train_futures.append(fut)
                    train_meta[fut] = (train_mac_key, ACTION_TRAIN)

                for f in as_completed(train_futures):
                    mac_key, action = train_meta[f]
                    try:
                        res: WorkerResult = f.result()
                    except Exception as e:
                        run_failed = True
                        logger.exception(f"Worker task failed: {type(e).__name__}: {e}")
                        device_report = create_device_report(mac_key, action, error=f"worker crashed before returning a result: {e}")
                        device_results[mac_key] = device_report
                        continue

                    log_text = (res.log or "").rstrip()
                    header = f"=== Worker log START device={mac_key} action={action} ok={res.ok} ==="
                    footer = f"=== Worker log END device={mac_key} ==="
                    logger.info("%s\n%s\n%s", header, log_text, footer)

                    # Either way, update the task carryover
                    task_carryovers[mac_key] = res.task_carryover

                    if not res.ok:
                        device_report = create_device_report(mac_key, action, error=log_text)
                        device_results[mac_key] = device_report
                        logger.info(f"Training failed for device {mac_key}: {log_text}")
                        run_failed = True
                        continue
                    else:
                        new_training_status = res.training_status
                        current_progress[mac_key] = new_training_status
                        update_device_training_status(progress_json_path, mac_key, new_training_status)
                        device_report = create_device_report(mac_key, action, device_status=new_training_status)
                        device_results[mac_key] = device_report
                        logger.info(f"Training completed, updated progress to {new_training_status} for device {mac_key}")

            analysis_ms = int((time.time() - start_wall) * 1000)
            logger.info(f"Processing completed in {analysis_ms}ms")

            # Compose final payload
            jan_niklas_reports = {mac_key: translate_result_to_janniklas(report) for mac_key, report in device_results.items()}
            flush_results(out_pipe, jan_niklas_reports, pcap_statistics, analysis_ms)
            
        except Exception as e:
            logger.exception("Top-level loop error: %s", e)
            flush_error(out_pipe, traceback.format_exc())

            # brief backoff to avoid tight error loop
            time.sleep(3.0)

########################################
# 7) Main entrypoint
########################################

def ml_analyze(ml_logger: object, pcap_in_pipe: str,out_pipe: str,devices_json_path: str,training_enabled: bool,progress_json_path: str) -> None:
    """
    Primary entrypoint. Runs forever: awaits PCAP, analyzes, writes result.
    """
    try:
        # Set up logger
        global logger 
        if not logger:
            if ml_logger:
                logger = ml_logger
            else:
                logger = _setup_logging()
                
        logger.info("Starting ml_analyze. training_enabled=%s", training_enabled)

        # Ensure dirs and files
        ROOT_SHARED.mkdir(parents=True, exist_ok=True)
        MODEL_DIRECTORY.mkdir(parents=True, exist_ok=True)
        DATASET_DIRECTORY.mkdir(parents=True, exist_ok=True)
        assert os.path.exists(BASE_MODEL_PATH), "Base model path does not exist"
        assert os.path.exists(COUNTRY_RECOGNITION_CSV_FILE), "Country recognition CSV file does not exist"
        assert os.path.exists(devices_json_path), "Devices JSON file does not exist"

        # Prepare ml components and load devices
        devices = load_user_devices(devices_json_path)  # mac_key -> info
        assert devices, "No devices found in given meta.json file"
        ensure_ml_components_for_devices(devices, progress_json_path)

        # Init resources
        load_country_recognition()
        task_carryovers = load_task_carryovers(devices)

        # Prepare worker pool
        n_workers = max(1, cpu_count() - 1)
        logger.info("Initializing worker pool with %d workers", n_workers)
        executor = ProcessPoolExecutor(max_workers=n_workers, initializer=_worker_initializer)

        ml_analysis_loop(pcap_in_pipe, out_pipe, training_enabled, task_carryovers, executor, devices, progress_json_path)   

    except Exception as e:
        set_state(ERROR)
        raise e

########################################
# 8) Manual test main
########################################

def testmain():
    parser = argparse.ArgumentParser(description="One-shot tester for ML analyzer.")
    parser.add_argument("--in-pipe", type=str, default="/tmp/ml_in.pcap", help="Named pipe to read PCAP from (pipe mode).")
    parser.add_argument("--out-pipe", type=str, default="/tmp/ml_out.json", help="Path to write JSON results.")
    parser.add_argument("--mkfifo", action="store_true", help="Create in-pipe as FIFO if it does not exist (pipe mode).")
    parser.add_argument("--devices-json", required=True, help="Path to devices meta.json")
    parser.add_argument("--progress-json", required=True, help="Path to training progress JSON")
    parser.add_argument("--training-enabled", action="store_true", help="Enable training decisions.")
    parser.add_argument("--workers", type=int, default=1, help="Worker processes for inference/collect (file mode only).")
    parser.add_argument("--base_directory", type=str, default="/config", help="Path to test base directory.")
    args = parser.parse_args()

    # Local filepaths for testing
    global TEST_MODE, BASE_MODEL_PATH, COUNTRY_RECOGNITION_CSV_FILE, ROOT_SHARED, MODEL_DIRECTORY, DATASET_DIRECTORY, LOG_DIRECTORY, THRESHOLD_FILENAME
    TEST_MODE = True

    ROOT_SHARED = Path(args.base_directory)
    if not ROOT_SHARED.exists():
        ROOT_SHARED.mkdir(parents=True, exist_ok=True)

    BASE_MODEL_PATH = os.path.abspath(os.path.join(args.base_directory, "..", "base_model.pt"))

    MODEL_DIRECTORY = ROOT_SHARED / "models"
    DATASET_DIRECTORY = ROOT_SHARED / "datasets"
    LOG_DIRECTORY = ROOT_SHARED / "logs"
    THRESHOLD_FILENAME = args.base_directory + "/anomaly_thresholds.json"
    # Construct path to ../IP2LOCATION-LITE-DB1.CSV/IP2LOCATION-LITE-DB1.CSV relative to base_directory
    ip2loc_dir = os.path.abspath(os.path.join(args.base_directory, "..", "IP2LOCATION-LITE-DB1.CSV"))
    COUNTRY_RECOGNITION_CSV_FILE = os.path.join(ip2loc_dir, "IP2LOCATION-LITE-DB1.CSV")

    logger = _setup_logging()

    logger.info("Using test mode: initialising normal pipe mode")
    # Pipe mode
    in_pipe = args.in_pipe
    # Make path absolute if it is a local path (not already absolute)
    if not os.path.isabs(in_pipe):
        in_pipe = os.path.abspath(in_pipe)
    logger.info(f"Absolute path: {in_pipe}")

    if not os.path.exists(in_pipe):
        os.mkfifo(in_pipe, 0o666)
        logger.info(f"Created FIFO: {in_pipe}")

    ml_analyze(logger, in_pipe, args.out_pipe, args.devices_json, args.training_enabled, args.progress_json)

if __name__ == "__main__":
    # Main is for testing only. Real entry point is ml_analyze()
    testmain()

"""
Open TODO's:

Optional:
- check improved windows builder (is last window accounted for properly?)
- Supress warning in window builder
- Improve training status progression + improve descriptions
- smart early stopping (iterative thresholding with outlier only training?)

"""