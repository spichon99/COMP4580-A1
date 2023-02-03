# COMP4580 - Assignment 1
# Sebastien Pichon - 7840237
# Usage: $python3 strToHex.py "<string>"

import sys
print(sys.argv[1].encode("utf-8").hex())
