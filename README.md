# How to Build
```terminal
git clone https://github.com/yamanalab/he-crusk.git
cd he-crusk
docker compose build
```

# How to Execute
```terminal
docker compose up -d
docker exec -it he-crusk /bin/bash
```

After entering the container, execute a following command.
```terminal
/app/build/benchmark/he_crusk/poly_func (#trials) (degree) (mode) (polynomial modulus degree) (scaling factor) (bits of moduli) (#moduli)
```

* #trials: #trials to execute the polynomial function. Large #trials requires large memory because each trial uses different HE keys.
* degree: degree of polynomial function. See `benchmark/he_crusk/poly_func.cpp` for supported degrees.
* mode: [HE-CRUSK|baseline|both]. `baseline` is execution w/o HE-CRUSK.
* polynomial modulus degree: Used for `polynomial_modulus_degree` for Microsoft SEAL.
* scaling factor: Scaling factor for an input ciphertext.
* bits of moduli: bits of moduli except for the first modulus and modulus for key-switching.
* #moduli: #moduli for an input ciphertext

## Example
w/ HE-CRUSK
```terminal
/app/build/benchmark/he_crusk/poly_func 101 7 HE-CRUSK 16384 40 60 6 > result_HE-CRUSK.txt
```

w/o HE-CRUSK
```terminal
/app/build/benchmark/he_crusk/poly_func 101 7 baseline 16384 40 40 4 > result_baseline.txt
```


# Summarize Execution Latency
Use `benchmark/he_crusk/summarize.sh` like the following.
```terminal
bash benchmark/he_crusk/summarize.sh result_HE-CRUSK.txt 101
```


