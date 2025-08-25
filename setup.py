#!/usr/bin/env python3
"""Minimal setup.py for pip compatibility.

This setup.py exists only for development installations and pip compatibility.
The actual package configuration is in pyproject.toml.

For installation, use:
    pip install -e .
    
For development:
    poetry install
"""

from setuptools import setup

# All configuration is in pyproject.toml
# This file exists for pip compatibility only
setup()
