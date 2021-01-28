#/bin/bash -eu
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

cd $GOPATH/src/github.com/filecoin-project/lotus
make

#mkdir fuzzing && cd fuzzing
#cp $GOPATH/src/github.com/filecoin-project/fuzzing-lotus/oss-fuzz/cbor/cbor_fuzzer.go .
#go clean -modcache

# Build first batch of fuzzers
compile_go_fuzzer github.com/filecoin-project/lotus/chain/types FuzzMessage fuzz_message
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzBlockMsg fuzz_block_msg
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzBlockMsgStructural fuzz_block_msg_structural
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzBlockHeader fuzz_block_header
compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/fuzz FuzzNodesForHeight fuzz_nodes_for_height

# Build next batch of fuzzers
declare -a arr=(
	"FuzzHelloMessageRaw" 
	"FuzzLatencyMessageRaw" 
	"FuzzVoucherInfoRaw" 
	"FuzzChannelInfoRaw" 
	"FuzzPaymentInfoRaw" 
	"FuzzSealedRefRaw" 
	"FuzzSealedRefsRaw" 
	"FuzzSealTicketRaw" 
	"FuzzSealSeedRaw" 
	"FuzzActorRaw" 
	"FuzzTipSetRaw" 
	"FuzzSignedMessageRaw" 
	"FuzzMsgMetaRaw" 
	"FuzzMessageReceiptRaw" 
	"FuzzDealProposalRaw" 
	"FuzzAddressRaw" 
	"FuzzDeferredRaw" 
	"FuzzKVRaw" 
	"FuzzNodeRaw" 
	"FuzzPointerRaw" 
	"FuzzNodeAmtRaw" 
	"FuzzRootAmtRaw" 
	"FuzzTestEventRaw" 
	"FuzzTestStateRaw" 
	"FuzzMarketWithdrawBalanceParamsRaw" 
	"FuzzPublishStorageDealsParamsRaw" 
	"FuzzComputeDataCommitmentParamsRaw" 
	"FuzzOnMinerSectorsTerminateParamsRaw" 
	"FuzzCreateMinerParamsRaw" 
	"FuzzEnrollCronEventParamsRaw" 
	"FuzzMinerConstructorParamsRaw" 
	"FuzzSubmitWindowedPoStParamsRaw" 
	"FuzzTerminateSectorsParamsRaw" 
	"FuzzChangePeerIDParamsRaw" 
	"FuzzProveCommitSectorParamsRaw" 
	"FuzzChangeWorkerAddressParamsRaw" 
	"FuzzExtendSectorExpirationParamsRaw" 
	"FuzzDeclareFaultsParamsRaw" 
	"FuzzDeclareFaultsRecoveredParamsRaw" 
	"FuzzReportConsensusFaultParamsRaw" 
	"FuzzCheckSectorProvenParamsRaw" 
	"FuzzMinerWithdrawBalanceParamsRaw" 
	"FuzzInitConstructorParamsRaw" 
	"FuzzExecParamsRaw" 
	"FuzzAddVerifierParamsRaw" 
	"FuzzAddVerifiedClientParamsRaw" 
	"FuzzUseBytesParamsRaw" 
	"FuzzRestoreBytesParamsRaw" 
	"FuzzCronConstructorParamsRaw" 
	"FuzzMultiSigConstructorParamsRaw" 
	"FuzzProposeParamsRaw" 
	"FuzzAddSignerParamsRaw" 
	"FuzzRemoveSignerParamsRaw" 
	"FuzzTxnIDParamsRaw" 
	"FuzzChangeNumApprovalsThresholdParamsRaw" 
	"FuzzSwapSignerParamsRaw" 
	"FuzzPaychConstructorParamsRaw" 
	"FuzzUpdateChannelStateParamsRaw" 
	"FuzzModVerifyParamsRaw" 
	"FuzzPaymentVerifyParamsRaw" 
	"FuzzAwardBlockRewardParamsRaw"
)

for i in "${arr[@]}"
do
   echo "$i"
   compile_go_fuzzer github.com/filecoin-project/fuzzing-lotus/oss-fuzz "$i" "$i"
done
