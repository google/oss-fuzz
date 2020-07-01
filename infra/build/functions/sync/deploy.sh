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

JOB_TOPIC=sync-topic
SCHEDULER_JOB=sync-scheduler
JOB_SCHEDULE="*/30 * * * *"
MESSAGE="Start Sync"
ENTRY_POINT=sync

# Checking if the given pubsub topic exists
if ! gcloud pubsub topics describe $JOB_TOPIC ;
	then
		gcloud pubsub topics create $JOB_TOPIC
fi
# Checking if the given scheduler job exists
if gcloud scheduler jobs describe $SCHEDULER_JOB;
	then
		gcloud scheduler jobs update pubsub sync-scheduler \
			--schedule "$JOB_SCHEDULE" \
			--topic $JOB_TOPIC \
			--message-body "$MESSAGE"
	else
		gcloud scheduler jobs create pubsub sync-scheduler \
			--schedule "$JOB_SCHEDULE" \
			--topic $JOB_TOPIC \
			--message-body "$MESSAGE"
fi

gcloud functions deploy sync \
	--entry-point $ENTRY_POINT \
	--trigger-topic $JOB_TOPIC \
	--runtime python37
