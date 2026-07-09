#!/usr/bin/env python3
# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import os
import sys

# Ensure the scripts/ directory is on sys.path so `import ghsa` resolves.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghsa.cli import cli  # noqa: E402

cli()
