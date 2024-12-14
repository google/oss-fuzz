FROM gcr.io/oss-fuzz-base/base-builder-python
COPY . $SRC/
# Clone the PSLab-Python repository into the source directory
RUN git clone --depth 1 https://github.com/fossasia/pslab-python.git $SRC/pslab-python

RUN python3 -m pip install --no-cache-dir -r $SRC/pslab-python/requirements.txt

COPY build.sh $SRC/

RUN bash $SRC/build.sh
