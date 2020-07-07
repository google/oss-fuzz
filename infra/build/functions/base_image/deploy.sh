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

JOB_TOPIC=schedule-base-image-build
SCHEDULER_JOB=base-image-scheduler
JOB_SCHEDULE="0 3 * * *"
MESSAGE="Start base image build"
ENTRY_POINT=base_builder

if [ "$1" ]; then
	PROJECT_ID=$1
else
	echo -e "\n Usage ./deploy.sh my-project-name"; exit;
fi

# Checking if the given pubsub topic exists
if ! gcloud pubsub topics describe $JOB_TOPIC --project $PROJECT_ID ;
	then
		gcloud pubsub topics create $JOB_TOPIC \
		--project $PROJECT_ID
fi
# Checking if the given scheduler job exists
if gcloud scheduler jobs describe $SCHEDULER_JOB --project $PROJECT_ID ;
	then
		gcloud scheduler jobs update pubsub $SCHEDULER_JOB \
			--schedule "$JOB_SCHEDULE" \
			--topic $JOB_TOPIC \
			--message-body "$MESSAGE" \
			--project $PROJECT_ID
	else
		gcloud scheduler jobs create pubsub $SCHEDULER_JOB \
			--schedule "$JOB_SCHEDULE" \
			--topic $JOB_TOPIC \
			--message-body "$MESSAGE" \
			--project $PROJECT_ID
fi

gcloud functions deploy base-image-build \
	--entry-point $ENTRY_POINT \
	--trigger-topic $JOB_TOPIC \
	--runtime python37 \
	--project $PROJECT_ID
