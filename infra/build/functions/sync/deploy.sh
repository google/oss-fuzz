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

SCHEDULE_JOB_TOPIC=schedule-project-sync
BUILD_JOB_TOPIC=request-build
SCHEDULER_JOB=sync-scheduler
JOB_SCHEDULE="*/30 * * * *"
MESSAGE="Start Sync"
ENTRY_POINT=sync

if [ "$1" ]; then
	PROJECT_ID=$1
else
	echo -e "\n Usage ./deploy.sh my-project-name"; exit;
fi

# All the individual project build schedulers will rely on this
if ! gcloud pubsub topics describe $BUILD_JOB_TOPIC --project $PROJECT_ID ;
	then
		gcloud pubsub topics create $BUILD_JOB_TOPIC \
		--project $PROJECT_ID
fi

# Checking if the given pubsub topic exists
if ! gcloud pubsub topics describe $SCHEDULE_JOB_TOPIC --project $PROJECT_ID ;
	then
		gcloud pubsub topics create $SCHEDULE_JOB_TOPIC \
		--project $PROJECT_ID
fi
# Checking if the given scheduler job exists
if gcloud scheduler jobs describe $SCHEDULER_JOB --project $PROJECT_ID ;
	then
		gcloud scheduler jobs update pubsub $SCHEDULER_JOB \
			--schedule "$JOB_SCHEDULE" \
			--topic $SCHEDULE_JOB_TOPIC \
			--message-body "$MESSAGE" \
			--project $PROJECT_ID
	else
		gcloud scheduler jobs create pubsub $SCHEDULER_JOB \
			--schedule "$JOB_SCHEDULE" \
			--topic $SCHEDULE_JOB_TOPIC \
			--message-body "$MESSAGE" \
			--project $PROJECT_ID
fi

gcloud functions deploy sync \
	--entry-point $ENTRY_POINT \
	--trigger-topic $SCHEDULE_JOB_TOPIC \
	--runtime python37 \
	--project $PROJECT_ID \
	--timeout 540
