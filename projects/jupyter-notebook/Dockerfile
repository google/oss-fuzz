FROM gcr.io/oss-fuzz-base/base-python

# Installa dipendenze di sistema
RUN apt-get update && apt-get install -y \
    git \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Installa Atheris (fuzzer Python)
RUN pip install atheris

# Installa Jupyter Notebook (versione vulnerabile per test)
RUN pip install notebook==7.0.6

# Clona il codice sorgente
RUN git clone --depth 1 https://github.com/jupyter/notebook.git $SRC

WORKDIR $SRC
COPY build.sh $SRC/
