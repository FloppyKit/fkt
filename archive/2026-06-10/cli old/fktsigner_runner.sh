#!/bin/bash
# Usage: fktsigner_runner.sh sign <input> <output> <seed_hex> [path]
SEED=$3
INPUT=$1
OUTPUT=$2
PATH=${4:-"84'/0'/0'/0/0"}   # default to known good path
./fktsigner "$SEED" "$PATH" "$INPUT" "$OUTPUT"