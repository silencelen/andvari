#!/usr/bin/env python3
"""Exit 0 when a binary contains a text, as UTF-8 or as UTF-16 (Kotlin/Native has stored literals both ways).

usage: binary-has-text.py <file> <text>
"""
import sys

data = open(sys.argv[1], "rb").read()
text = sys.argv[2]
sys.exit(0 if text.encode("utf-8") in data or text.encode("utf-16-le") in data else 1)
