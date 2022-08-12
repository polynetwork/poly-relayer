package neo3

import "github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"

func convertNeoTmvToEthTmv(neoTmv *ToMerkleValue) *common.ToMerkleValue {
	return &common.ToMerkleValue{
		TxHash:      neoTmv.TxHash,
		FromChainID: neoTmv.FromChainID,
		MakeTxParam: convertNeoParamToEthParam(neoTmv.TxParam),
	}
}

func convertNeoParamToEthParam(neoParam *CrossChainTxParameter) *common.MakeTxParam {
	return &common.MakeTxParam{
		TxHash:              neoParam.TxHash,
		CrossChainID:        neoParam.CrossChainID,
		FromContractAddress: neoParam.FromContract,
		ToChainID:           neoParam.ToChainID,
		ToContractAddress:   neoParam.ToContract,
		Method:              string(neoParam.Method),
		Args:                neoParam.Args,
	}
}

func convertEthTmvToNeoTmv(ethTmv *common.ToMerkleValue) *ToMerkleValue {
	return &ToMerkleValue{
		TxHash:      ethTmv.TxHash,
		FromChainID: ethTmv.FromChainID,
		TxParam:     convertEthParamToNeoParam(ethTmv.MakeTxParam),
	}
}

func convertEthParamToNeoParam(ethParam *common.MakeTxParam) *CrossChainTxParameter {
	return &CrossChainTxParameter{
		TxHash:       ethParam.TxHash,
		CrossChainID: ethParam.CrossChainID,
		FromContract: ethParam.FromContractAddress,
		ToChainID:    ethParam.ToChainID,
		ToContract:   ethParam.ToContractAddress,
		Method:       []byte(ethParam.Method),
		Args:         ethParam.Args,
	}
}
