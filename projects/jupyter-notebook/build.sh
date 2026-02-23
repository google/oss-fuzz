#!/bin/bash -eu

# Installa dipendenze
pip install -r $SRC/requirements.txt

# Installa Atheris
pip install atheris

# Copia fuzz target
cp $SRC/projects/jupyter-notebook/fuzz_notebook.py $OUT/

# Crea seed corpus (il tuo PoC RCE)
mkdir -p $OUT/corpus
echo "__import__('os').system('id')" > $OUT/corpus/seed1.py

# Build (Python fuzzers sono script)
cp $OUT/fuzz_notebook.py $OUT/fuzz_notebook
