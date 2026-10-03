#!/usr/bin/env python3
"""Repository entry point for the SDK-owned offline input checker."""
import runpy
from pathlib import Path

if __name__ == '__main__':
    runpy.run_path(str(Path(__file__).resolve().parents[1] / 'sdk/c/build/check-native-sources.py'), run_name='__main__')
