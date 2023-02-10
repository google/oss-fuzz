#!/bin/bash -ex
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

COVERAGE_BUILD_JOB_TOPIC=request-coverage-build
INTROSPECTOR_BUILD_JOB_TOPIC=request-introspector-build

SYNC_JOB_TOPIC=schedule-project-sync
SYNC_SCHEDULER_JOB=sync-scheduler
SYNC_JOB_SCHEDULE="*/30 * * * *"
SYNC_MESSAGE="Start Sync"

function deploy_pubsub_topic {
	topic=$1
	project=$2

	if ! gcloud pubsub topics describe $topic --project $project ;
		then
			gcloud pubsub topics create $topic \
			--project $project
	fi
}

function deploy_scheduler {
	scheduler_name=$1
	schedule="$2"
	topic=$3
	message="$4"
	project=$5

	if gcloud scheduler jobs describe $scheduler_name --project $project ;
		then
			gcloud scheduler jobs update pubsub $scheduler_name \
			--project $project \
			--schedule "$schedule" \
			--topic $topic \
			--message-body "$message"
		else
			gcloud scheduler jobs create pubsub $scheduler_name \
			--project $project \
			--schedule "$schedule" \
			--topic $topic \
			--message-body "$message"
	fi
}

function deploy_cloud_function {
	name=$1
	entry_point=$2
	topic=$3
	project=$4

	gcloud functions deploy $name \
	--entry-point $entry_point \
	--trigger-topic $topic \
	--runtime python38 \
	--project $project \
	--timeout 540 \
	--region us-central1 \
	--set-env-vars GCP_PROJECT=$project,FUNCTION_REGION=us-central1 \
	--max-instances 1 \
	--memory 4096MB
}

if [ $# == 1 ]; then
	PROJECT_ID=$1
else
	echo -e "\n Usage ./deploy.sh <project-name>"; exit;
fi

deploy_pubsub_topic $BUILD_JOB_TOPIC $PROJECT_ID
deploy_pubsub_topic $SYNC_JOB_TOPIC $PROJECT_ID
deploy_pubsub_topic $BASE_IMAGE_JOB_TOPIC $PROJECT_ID
deploy_pubsub_topic $COVERAGE_BUILD_JOB_TOPIC $PROJECT_ID
deploy_pubsub_topic $INTROSPECTOR_BUILD_JOB_TOPIC $PROJECT_ID

deploy_scheduler $SYNC_SCHEDULER_JOB \
				 "$SYNC_JOB_SCHEDULE" \
				 $SYNC_JOB_TOPIC \
				 "$SYNC_MESSAGE" \
				  $PROJECT_ID

deploy_scheduler $BASE_IMAGE_SCHEDULER_JOB \
				 "$BASE_IMAGE_SCHEDULE" \
				  $BASE_IMAGE_JOB_TOPIC \
				  "$BASE_IMAGE_MESSAGE" \
				  $PROJECT_ID

deploy_cloud_function sync \
					  sync \
					  $SYNC_JOB_TOPIC \
					  $PROJECT_ID

deploy_cloud_function base-image-build \
					  build_base_images \
					  $BASE_IMAGE_JOB_TOPIC \
					  $PROJECT_ID

deploy_cloud_function request-build \
					  build_project \
					  $BUILD_JOB_TOPIC \
					  $PROJECT_ID

deploy_cloud_function request-coverage-build \
					  coverage_build \
					  $COVERAGE_BUILD_JOB_TOPIC \
					  $PROJECT_ID

deploy_cloud_function request-introspector-build \
					  introspector_build \
					  $INTROSPECTOR_BUILD_JOB_TOPIC \
					  $PROJECT_ID

gcloud datastore indexes create index.yaml --project $PROJECT_ID
