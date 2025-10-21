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

cd "$SRC"/kubevirt

cp -r $SRC/kubevirt-fuzz1/pkg/virt-operator/resource/apply/fuzz $SRC/kubevirt/pkg/virt-operator/resource/apply/
cp -r $SRC/kubevirt-fuzz2/pkg/virt-controller/watch/clone/fuzz $SRC/kubevirt/pkg/virt-controller/watch/clone/
cp -r $SRC/kubevirt-fuzz2/pkg/virt-controller/watch/clone/utils_fuzz.go $SRC/kubevirt/pkg/virt-controller/watch/clone/
cp -r $SRC/kubevirt-fuzz3/pkg/virt-controller/watch/vm/fuzz $SRC/kubevirt/pkg/virt-controller/watch/vm/
cp -r $SRC/kubevirt-fuzz3/pkg/virt-controller/watch/vmi/fuzz $SRC/kubevirt/pkg/virt-controller/watch/vmi/
mv $SRC/kubevirt/pkg/virt-controller/watch/vm/patchreactor_test.go $SRC/kubevirt/pkg/virt-controller/watch/vm/patchreactor.go
mv $SRC/kubevirt/pkg/virt-controller/watch/vm/updatereactor_test.go $SRC/kubevirt/pkg/virt-controller/watch/vm/updatereactor.go

cp -r $SRC/kubevirt-fuzz4/pkg/virt-controller/watch/node/fuzz $SRC/kubevirt/pkg/virt-controller/watch/node/
cp -r $SRC/kubevirt-fuzz4/pkg/virt-controller/watch/node/util.go $SRC/kubevirt/pkg/virt-controller/watch/node/
cp -r $SRC/kubevirt-fuzz5/pkg/virt-controller/watch/drain/disruptionbudget/fuzz $SRC/kubevirt/pkg/virt-controller/watch/drain/disruptionbudget/
cp -r $SRC/kubevirt-fuzz5/pkg/virt-controller/watch/migration/fuzz $SRC/kubevirt/pkg/virt-controller/watch/migration/
cp -r $SRC/kubevirt-fuzz5/pkg/virt-controller/watch/pool/fuzz $SRC/kubevirt/pkg/virt-controller/watch/pool/
cp -r $SRC/kubevirt-fuzz5/pkg/virt-controller/watch/pool/util.go $SRC/kubevirt/pkg/virt-controller/watch/pool/
cp -r $SRC/kubevirt-fuzz6/pkg/virt-operator/resource/generate/install/fuzz $SRC/kubevirt/pkg/virt-operator/resource/generate/install/
cp -r $SRC/kubevirt-fuzz7/pkg/virt-api/webhooks/mutating-webhook/fuzz_test.go $SRC/kubevirt/pkg/virt-api/webhooks/mutating-webhook/
cp -r $SRC/kubevirt-fuzz7/pkg/virt-api/webhooks/validating-webhook/fuzz_test.go $SRC/kubevirt/pkg/virt-api/webhooks/validating-webhook/

go mod tidy
go work vendor

find . -type f -name "fuzz_suite_test.go" -delete
rm pkg/virt-operator/resource/generate/install/install_suite_test.go
# this t.Fail() is not OSS-Fuzz friendly and creates false crashes
sed -i 's/t\.Fail()/return/g' pkg/virt-api/webhooks/fuzz/fuzz_test.go
# remove logging from fuzzer
sed -i 's/fmt\.Println(string(j))/_ = j/g' pkg/virt-api/webhooks/fuzz/fuzz_test.go
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-api/webhooks/mutating-webhook FuzzWebhookMutators FuzzWebhookMutators
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-api/webhooks/validating-webhook FuzzWebhookAdmitters FuzzWebhookAdmitters
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-api/webhooks/fuzz FuzzAdmitter FuzzAdmitter
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/install/fuzz FuzzLoadInstallStrategyFromCache FuzzLoadInstallStrategyFromCache
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/node/fuzz FuzzExecute FuzzNodeWatchExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/vm/fuzz FuzzExecute FuzzVMWatchExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/vmi/fuzz FuzzExecute FuzzVMIWatchExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/clone/fuzz FuzzVMCloneController FuzzVMCloneController
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-operator/resource/apply/fuzz FuzzReconciler FuzzVirtOperatorResApplyReconciler
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/drain/disruptionbudget/fuzz FuzzExecute FuzzWatchDrainDisruptionBudgetExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/migration/fuzz FuzzExecute FuzzWatchMigrationExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/pool/fuzz FuzzExecute FuzzWatchPoolExecute

mv $SRC/fuzz_test.go ./pkg/certificates/triple/cert/
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/certificates/triple/cert FuzzKeyParsers FuzzKeyParsers

mv $SRC/fuzz_loadInstallStrategyFromBytes_test.go ./pkg/virt-operator/resource/generate/install/
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/install FuzzLoadInstallStrategyFromBytes FuzzLoadInstallStrategyFromBytes

cp $SRC/*.options $OUT/
