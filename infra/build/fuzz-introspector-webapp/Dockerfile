# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
FROM python:3.11-bullseye

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

RUN git clone --depth=1 https://github.com/ossf/fuzz-introspector /fuzz-introspector

# Copy local code to the container image.
ENV APP_HOME /fuzz-introspector/tools/web-fuzzing-introspection/app/
WORKDIR $APP_HOME

# Install production dependencies.
RUN pip install --no-cache-dir -r $APP_HOME/../requirements.txt

# Create the database the webapp will be using
RUN cd $APP_HOME/static/assets/db/ && \
    python ./web_db_creator_from_summary.py \
      --since-date=20-04-2023 \
      --output-dir=$PWD \
      --input-dir=$PWD

ENV WEBAPP_PORT 8080
ENV G_ANALYTICS_TAG "G-VDH9DCD8T8"

RUN pip install gunicorn==20.1.0

# Run the web service on container startup. Here we use the gunicorn
# webserver, with one worker process and 8 threads.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
# Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling.
CMD exec gunicorn --bind :${WEBAPP_PORT} --workers 1 --threads 8 --timeout 0 'main:create_app()'
