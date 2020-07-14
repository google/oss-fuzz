# Copyright 2020 Google Inc.
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

JOB_TOPIC=request-build
ENTRY_POINT=request_build

if [ "$1" ]; then
	PROJECT_ID=$1
else
	echo -e "\n Usage ./deploy.sh my-project-name"; exit;
fi

gcloud functions deploy request-build \
	--entry-point $ENTRY_POINT \
	--trigger-topic $JOB_TOPIC \
	--runtime python37 \
	--project $PROJECT_ID
