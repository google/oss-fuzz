package smr

import (
	"testing"

	"github.com/xuperchain/xuperchain/core/consensus/common/chainedbft/utils"
	"github.com/xuperchain/xuperchain/core/pb"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func init() {
	testing.Init()
}

func Fuzz(data []byte) int {
	t := &testing.T{}
	f := fuzz.NewConsumer(data)
	pubKey, err := f.GetString()
	if err != nil {
		return 0
	}
	privateKey, err := f.GetString()
	if err != nil {
		return 0
	}
	msg, err := f.GetBytes()
	if err != nil {
		return 0
	}

	smr, err := MakeSmr(t)
	if err != nil {
		return 0
	}

	propsQC := &pb.QuorumCert{
		ProposalId:  []byte("propsQC ProposalId"),
		ProposalMsg: []byte("propsQC ProposalMsg"),
		Type:        pb.QCState_PREPARE,
		ViewNumber:  1002,
	}
	justify := &pb.QuorumCert{
		ProposalId:  []byte("justify ProposalId"),
		ProposalMsg: []byte("justify ProposalMsg"),
		Type:        pb.QCState_PREPARE,
		ViewNumber:  1001,
		SignInfos: &pb.QCSignInfos{
			QCSignInfos: []*pb.SignInfo{},
		},
	}
	signInfo := &pb.SignInfo{
		Address:   `dpzuVdosQrF2kmzumhVeFQZa1aYcdgFpN`,
		PublicKey: pubKey,
	}
	priKey, _ := smr.cryptoClient.GetEcdsaPrivateKeyFromJSON([]byte(privateKey))

	signInfo, err = utils.MakeVoteMsgSign(smr.cryptoClient, priKey, signInfo, msg)
	if err != nil {
		return 0
	}
	signInfos := []*pb.SignInfo{}
	signInfos = append(signInfos, signInfo)
	justify.SignInfos.QCSignInfos = signInfos
	if _, err = smr.safeProposal(propsQC, justify); err == nil {
		return 0
	}
	smr.lockedQC.ViewNumber = 1000
	if _, err = smr.safeProposal(propsQC, justify); err != nil {
		return 0
	}
	return 1
}
