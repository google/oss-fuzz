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

BASE_IMAGE_JOB_TOPIC=schedule-base-image-build
BASE_IMAGE_SCHEDULER_JOB=base-image-scheduler
BASE_IMAGE_SCHEDULE="0 3 * * *"
BASE_IMAGE_MESSAGE="Start base image build"

BUILD_JOB_TOPIC=request-build

SYNC_JOB_TOPIC=schedule-project-sync
SYNC_SCHEDULER_JOB=sync-scheduler
SYNC_JOB_SCHEDULE="*/30 * * * *"
SYNC_MESSAGE="Start Sync"



if [ "$1" ]; then
	PROJECT_ID=$1
else
	echo -e "\n Usage ./deploy.sh my-project-name"; exit;
fi


if ! gcloud pubsub topics describe $BUILD_JOB_TOPIC --project $PROJECT_ID ;
	then
		gcloud pubsub topics create $BUILD_JOB_TOPIC \
		--project $PROJECT_ID
fi


if ! gcloud pubsub topics describe $SYNC_JOB_TOPIC --project $PROJECT_ID ;
	then
		gcloud pubsub topics create $SYNC_JOB_TOPIC \
		--project $PROJECT_ID
fi

if gcloud scheduler jobs describe $SYNC_SCHEDULER_JOB --project $PROJECT_ID ;
	then
		gcloud scheduler jobs update pubsub $SYNC_SCHEDULER_JOB \
			--schedule "$SYNC_JOB_SCHEDULE" \
			--topic $SYNC_JOB_TOPIC \
			--message-body "$SYNC_MESSAGE" \
			--project $PROJECT_ID
	else
		gcloud scheduler jobs create pubsub $SYNC_SCHEDULER_JOB \
			--schedule "$SYNC_JOB_SCHEDULE" \
			--topic $SYNC_JOB_TOPIC \
			--message-body "$SYNC_MESSAGE" \
			--project $PROJECT_ID
fi

gcloud functions deploy sync \
	--entry-point project_sync \
	--trigger-topic $SYNC_JOB_TOPIC \
	--runtime python37 \
	--project $PROJECT_ID \
	--timeout 540

if ! gcloud pubsub topics describe $BASE_IMAGE_JOB_TOPIC --project $PROJECT_ID ;
	then
		gcloud pubsub topics create $BASE_IMAGE_JOB_TOPIC \
		--project $PROJECT_ID
fi

if gcloud scheduler jobs describe $BASE_IMAGE_SCHEDULER_JOB --project $PROJECT_ID ;
	then
		gcloud scheduler jobs update pubsub $BASE_IMAGE_SCHEDULER_JOB \
			--schedule "$BASE_IMAGE_SCHEDULE" \
			--topic $BASE_IMAGE_JOB_TOPIC \
			--message-body "$BASE_IMAGE_MESSAGE" \
			--project $PROJECT_ID
	else
		gcloud scheduler jobs create pubsub $BASE_IMAGE_SCHEDULER_JOB \
			--schedule "$BASE_IMAGE_SCHEDULE" \
			--topic $BASE_IMAGE_JOB_TOPIC \
			--message-body "$BASE_IMAGE_MESSAGE" \
			--project $PROJECT_ID
fi

gcloud functions deploy base-image-build \
	--entry-point build_base_images \
	--trigger-topic $BASE_IMAGE_JOB_TOPIC \
	--runtime python37 \
	--project $PROJECT_ID


gcloud functions deploy request-build \
	--entry-point build_project \
	--trigger-topic $BUILD_JOB_TOPIC \
	--runtime python37 \
	--project $PROJECT_ID