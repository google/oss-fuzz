#!/bin/bash
# Copyright 2016 Google Inc.
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

set -x

PROJECT="gcr.io/meta-iterator-105109"
DIR=$(dirname $0)

docker build --pull -t $PROJECT/jenkins $DIR/
gcloud docker push $PROJECT/jenkins

# delete jenkins-master if it exists before starting
kubectl get petset jenkins-master
if [ $? -eq 0 ]
then
  kubectl delete -f $DIR/jenkins-master.yaml
fi
kubectl create -f $DIR/jenkins-master.yaml

# do not restart services to keep IP addresses stable.
kubectl get service jenkins-http
if [ $? -ne 0 ]
then
  kubectl create -f $DIR/service-jenkins-http.yaml
fi
kubectl get service jenkins-master
if [ $? -ne 0 ]
then
  kubectl create -f $DIR/service-jenkins-master.yaml
fi

kubectl describe petset jenkins-master
kubectl describe service jenkins-http
