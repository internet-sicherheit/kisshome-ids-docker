#!/bin/bash

# Run the Flask API in the foreground (blocking) with gunicorn
# Also use 1 worker and 2 threads to keep it as lightweight as possible
#python3 /app/flask_api.py # Developement server
exec gunicorn --workers=1 --threads=2 --bind 0.0.0.0:5000 flask_api:app