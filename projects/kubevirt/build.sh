#!/bin/bash -eu
# Copyright 2024 Google LLC
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

cd "$SRC"/go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/
cd "$SRC"/kubevirt

cp $SRC/kubevirt-fuzz1/pkg/virt-operator/resource/apply/fuzz_test.go $SRC/kubevirt/pkg/virt-operator/resource/apply/
cp $SRC/kubevirt-fuzz2/pkg/virt-controller/watch/clone/fuzz_test.go $SRC/kubevirt/pkg/virt-controller/watch/clone/
cp $SRC/kubevirt-fuzz3/pkg/virt-controller/watch/vm/fuzz_test.go $SRC/kubevirt/pkg/virt-controller/watch/vm/
cp $SRC/kubevirt-fuzz3/pkg/virt-controller/watch/vmi/fuzz_test.go $SRC/kubevirt/pkg/virt-controller/watch/vmi/
cp $SRC/kubevirt-fuzz4/pkg/virt-controller/watch/node/fuzz_test.go $SRC/kubevirt/pkg/virt-controller/watch/node/
cp $SRC/kubevirt-fuzz5/pkg/virt-controller/watch/drain/disruptionbudget/fuzz_test.go $SRC/kubevirt/pkg/virt-controller/watch/drain/disruptionbudget/
cp $SRC/kubevirt-fuzz5/pkg/virt-controller/watch/migration/fuzz_test.go $SRC/kubevirt/pkg/virt-controller/watch/migration/
cp $SRC/kubevirt-fuzz5/pkg/virt-controller/watch/pool/fuzz_test.go $SRC/kubevirt/pkg/virt-controller/watch/pool/
cp $SRC/kubevirt-fuzz6/pkg/virt-operator/resource/generate/install/fuzz_test.go $SRC/kubevirt/pkg/virt-operator/resource/generate/install/
cp $SRC/kubevirt-fuzz7/pkg/virt-api/webhooks/mutating-webhook/fuzz_test.go $SRC/kubevirt/pkg/virt-api/webhooks/mutating-webhook/
cp $SRC/kubevirt-fuzz7/pkg/virt-api/webhooks/validating-webhook/fuzz_test.go $SRC/kubevirt/pkg/virt-api/webhooks/validating-webhook/

printf "package webhooks\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > pkg/util/webhooks/register_fuzz_dep.go
go mod tidy
go mod vendor
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build="$SRC"/go-118-fuzz-build
go mod tidy
go mod vendor

compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-api/webhooks/mutating-webhook FuzzWebhookMutators FuzzWebhookMutators
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-api/webhooks/validating-webhook FuzzWebhookAdmitters FuzzWebhookAdmitters
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-api/webhooks/fuzz FuzzAdmitter FuzzAdmitter
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/install FuzzLoadInstallStrategyFromCache FuzzLoadInstallStrategyFromCache
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-controller/watch/node FuzzExecute FuzzNodeWatchExecute
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-controller/watch/vm FuzzExecute FuzzVMWatchExecute
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-controller/watch/vmi FuzzExecute FuzzVMIWatchExecute
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-controller/watch/clone FuzzVMCloneController FuzzVMCloneController
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-operator/resource/apply FuzzReconciler FuzzVirtOperatorResApplyReconciler
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-controller/watch/drain/disruptionbudget FuzzExecute FuzzWatchDrainDisruptionBudgetExecute
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-controller/watch/migration FuzzExecute FuzzWatchMigrationExecute
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-controller/watch/pool FuzzExecute FuzzWatchPoolExecute

mv $SRC/fuzz_test.go ./pkg/certificates/triple/cert/
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/certificates/triple/cert FuzzKeyParsers FuzzKeyParsers

mv $SRC/fuzz_loadInstallStrategyFromBytes_test.go ./pkg/virt-operator/resource/generate/install/
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/install FuzzLoadInstallStrategyFromBytes FuzzLoadInstallStrategyFromBytes

cp $SRC/*.options $OUT/
