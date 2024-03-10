#!/usr/bin/env python3
# og author: utaha1228

KEY_SIZE = 32
OUTPUT_FILE = "global_secrets.h"

with open("/dev/random", "rb") as f:
    secret = f.read(KEY_SIZE).hex()

# TODO WARNING CRITICAL THIS IS BAD AND ONLY
# SERVES TO MAKE TESTING LESS ANNOYING
# REMOVE THIS OR EVERYTHING IS DOOMED
secret = "0"*64
# REMOVE THIS OR EVERYTHING IS DOOMED

secret_c_str = "".join(["\\x" + secret[i:i+2] for i in range(0, len(secret), 2)])

output = f"""\
#define SHARED_SECRET_KEY (uint8_t *)("{secret_c_str}")
"""

with open(OUTPUT_FILE, "w") as f:
	f.write(output)
