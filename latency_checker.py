#!/usr/bin/env python3
"""Latency Checker is now two programs:

  latency_logger.py  – headless logger (can run as a service at boot)
  latency_viewer.py  – the graph window

This file just opens the viewer, so old shortcuts keep working.
"""
import runpy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
runpy.run_path(str(Path(__file__).resolve().parent / "latency_viewer.py"), run_name="__main__")
