#!/bin/bash

fp="$1"
n=$2

keywords=(
    "encrypt and randomize (variable)"
    "encrypt and randomize (constant)"
    "exec (HE-CRUSK)"
    "decrypt (HE-CRUSK)"
    
    "encrypt (baseline) (variable)"
    "encrypt (baseline) (constant)"
    "exec (baseline)"
    "decrypt (baseline)"
)

for key in "${keywords[@]}"; do
    if [ -z "`grep -e "${key}" ${fp}`" ]; then
        continue
    fi
    echo ${key}
    grep -e "${key}" -A${n} ${fp} | grep -v "${key}" | tail -$((${n} - 1)) | awk '{S+=$2};END{print S/NR}'
done
