#!/usr/bin/env python3
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
Slim Autoencoder for anomaly detection.

- Architecture: MLP Autoencoder (reconstruct_all)
- Input dim = 45
- Encoder: 45→64→32→16→latent(8) with ReLU between linear layers
- Decoder: 8→16→32→64→45 with ReLU between linear layers
- Loss: MSE (mean)
"""
from __future__ import annotations
from typing import Any

from torch import Tensor, no_grad, from_numpy, save, load, inference_mode, enable_grad, set_num_threads
from torch.nn import Module, Sequential, Linear, ReLU, MSELoss
from torch.nn.utils import clip_grad_norm_
from torch.optim import Adam

import numpy as np

BATCH_SIZE = 16 # Small batch size since dataset is small 
EPOCHS = 3  # 3 epochs should be enough for a small dataset
LEARNING_RATE = 1e-4 # 

# ------------------------------------------------------------
# Fixed Model (vector input only)
# ------------------------------------------------------------

class Autoencoder(Module):
    """Fixed MLP Autoencoder for 45-dim vectors → reconstruct_all."""

    def __init__(self):
        super().__init__()

        input_dim = 45
        latent_dim = 8

        # Encoder base + projection to latent
        self.encoder = Sequential(
            Linear(input_dim, 64), ReLU(),
            Linear(64, 32), ReLU(),
            Linear(32, 16), ReLU(),
            Linear(16, latent_dim),
        )

        # Decoder base + projection back to original dim
        self.decoder = Sequential(
            Linear(latent_dim, 16), ReLU(),
            Linear(16, 32), ReLU(),
            Linear(32, 64), ReLU(),
            Linear(64, input_dim),
        )

        # Loss objects mirroring your original pattern (train vs score)
        self.loss_train: MSELoss = MSELoss(reduction="mean")
        self.loss_score: MSELoss = MSELoss(reduction="none")

    def forward(self, x: Tensor) -> Tensor:
        """x: (B, 45) → (B, 45)"""
        z = self.encoder(x)
        out = self.decoder(z)
        return out

    # --------------------------------------------------------
    # Loss and anomaly score helpers (vector reconstruct_all)
    # --------------------------------------------------------
    def compute_loss(self, batch: Tensor) -> Tensor:
        """Expect batch as (input_x, eval_label)."""
        pred = self(batch)
        return self.loss_train(pred, batch) # We do reconstruction, so the target is the input

    @no_grad()
    def compute_anomaly_score(self, batch: Tensor) -> Tensor:
        """Return per-sample MSE (B,) and pass-through labels.""" #TODO: check if the last parts of this func are necessary here
        # Do a forward pass on the pcap data
        pred = self(batch)

        err = self.loss_score(pred, batch)          # (B, 45)
        dims = tuple(range(1, err.ndim))             # all non-batch axes
        scores = err.mean(dim=dims).detach()         # (B,)
        return scores

# ------------------------------------------------------------
# Save / Load (no config required)
# ------------------------------------------------------------

def save_model(model: Autoencoder, model_path: str) -> None:
    # Only store weights; architecture is fixed and recreated on load
    save({"state_dict": model.state_dict()}, model_path)

def load_model(model_path: str, map_location: str = "cpu") -> Autoencoder:
    try:
        ckpt = load(model_path, map_location=map_location)
        model = Autoencoder()
        model.load_state_dict(ckpt["state_dict"]) 
        return model
    except Exception as e:
        return None

def infer(model: Autoencoder, features: np.ndarray) -> np.ndarray:
    # Turn into tensor and float
    features = from_numpy(features).float()
    
    inference_mode()
    scores = model.compute_anomaly_score(features)

    # Turn into numpy array
    scores = scores.detach().numpy()
    return scores

def finetune(model: Autoencoder, features: np.ndarray) -> Any:    
    opt = Adam(model.parameters(), lr=LEARNING_RATE)

    model.train()
    with enable_grad():   
        for epoch in range(EPOCHS):
            for i in range(0, features.shape[0], BATCH_SIZE):
                batch = features[i:i+BATCH_SIZE]
                # Turn into tensor and float
                tensor_batch = from_numpy(batch).float()
                loss = model.compute_loss(tensor_batch) # mean over batch
                loss.backward()
                clip_grad_norm_(model.parameters(), max_norm=1.0)
                opt.step()
                opt.zero_grad()

    # Do final epoch focusing on outliers
    scores = infer(model, features)
    upper_score_limit = np.sort(scores)[int(len(scores) * 0.60)]
    upper_feature_mask = scores > upper_score_limit
    upper_features = features[upper_feature_mask]

    model.train()
    with enable_grad():   
        for epoch in range(1):
            for i in range(0, upper_features.shape[0], BATCH_SIZE):
                batch = upper_features[i:i+BATCH_SIZE]
                # Turn into tensor and float
                tensor_batch = from_numpy(batch).float()
                loss = model.compute_loss(tensor_batch) # mean over batch
                loss.backward()
                clip_grad_norm_(model.parameters(), max_norm=1.0)
                opt.step()
                opt.zero_grad()


def set_torch_threads_1() -> None:
    set_num_threads(1)
