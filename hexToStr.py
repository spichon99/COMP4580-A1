# COMP4580 - Assignment 1
# Sebastien Pichon - 7840237
# Usage: $python3 hexToStr.py <hex>

import sys
import codecs
decode_hex = codecs.getdecoder("hex_codec")
print(decode_hex(sys.argv[1])[0])
