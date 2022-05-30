package poly

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ontio/ontology-crypto/keypair"
	vconf "github.com/ontio/ontology/consensus/vbft/config"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	scom "github.com/polynetwork/poly-go-sdk/common"
	pcom "github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	ccom "github.com/polynetwork/poly/native/service/cross_chain_manager/common"

	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

func (s *Submitter) GetProof(height uint32, key string) (param *ccom.ToMerkleValue, auditPath string, evt *scom.SmartContactEvent, err error) {
	proof, err := s.sdk.Node().GetCrossStatesProof(height, key)
	if err != nil {
		err = fmt.Errorf("GetProof: GetCrossStatesProof key %s, error %v", key, err)
		return
	}
	auditPath = proof.AuditPath
	path, err := hex.DecodeString(proof.AuditPath)
	if err != nil {
		return
	}
	value, _, _, _ := msg.ParseAuditPath(path)
	param = new(ccom.ToMerkleValue)
	err = param.Deserialization(pcom.NewZeroCopySource(value))
	if err != nil {
		err = fmt.Errorf("GetPolyParams: param.Deserialization error %v", err)
	}
	return
}

func (s *Submitter) GetPolyParams(tx *msg.Tx) (param *ccom.ToMerkleValue, path string, evt *scom.SmartContactEvent, err error) {
	if tx.PolyHash == "" {
		err = fmt.Errorf("ComposeTx: Invalid poly hash")
		return
	}

	if tx.PolyHeight == 0 {
		tx.PolyHeight, err = s.sdk.Node().GetBlockHeightByTxHash(tx.PolyHash)
		if err != nil {
			return
		}
	}

	if tx.PolyKey != "" {
		return s.GetProof(tx.PolyHeight, tx.PolyKey)
	}

	switch tx.DstChainId {
	case base.FLOW:
		if len(tx.Subject) != 0 {
			param = &ccom.ToMerkleValue{}
			err = param.Deserialization(pcom.NewZeroCopySource(tx.Subject))
			if err != nil {
				err = fmt.Errorf("deserialization subject error=%s", err)
			}
		}
		return
	}

	evt, err = s.sdk.Node().GetSmartContractEvent(tx.PolyHash)
	if err != nil {
		return
	}

	for _, notify := range evt.Notify {
		states := notify.States.([]interface{})
		switch notify.ContractAddress {
		case poly.CCM_ADDRESS:
			if len(states) < 6 {
				continue
			}
			param, path, evt, err = s.GetProof(tx.PolyHeight, states[5].(string))
			if err != nil {
				log.Error("GetPolyParams: param.Deserialization error", "err", err)
			} else {
				return
			}
		case poly.SM_ADDRESS:
			if len(states) < 4 {
				continue
			}
			if sigKey, e := base64.StdEncoding.DecodeString(states[1].(string)); e != nil {
				err = fmt.Errorf("GetPolyParams: decode sig error=%s", e)
			} else {
				tx.SigStorage, err = s.sdk.Node().GetStorage(poly.SM_ADDRESS, append([]byte("sigInfo"), sigKey...))
			}
			tx.Subject, err = base64.StdEncoding.DecodeString(states[2].(string))
			if err != nil {
				log.Error("GetPolyParams: decode subject error", "err", err)
			} else {
				param = &ccom.ToMerkleValue{}
				err = param.Deserialization(pcom.NewZeroCopySource(tx.Subject))
				if err != nil {
					log.Error("GetPolyParams: deserialization subject error", "err", err)
				} else {
					return
				}
			}
		}
	}
	err = fmt.Errorf("Valid ToMerkleValue not found")
	return
}

func (s *Submitter) ComposeTx(tx *msg.Tx) (err error) {
	if tx.PolyHash == "" {
		return fmt.Errorf("ComposeTx: Invalid poly hash")
	}
	/*
		if tx.DstPolyEpochStartHeight == 0 {
			return fmt.Errorf("ComposeTx: Dst chain poly height not specified")
		}
	*/

	if tx.PolyHeight == 0 {
		tx.PolyHeight, err = s.sdk.Node().GetBlockHeightByTxHash(tx.PolyHash)
		if err != nil {
			return
		}
	}
	tx.PolyHeader, err = s.sdk.Node().GetHeaderByHeight(tx.PolyHeight + 1)
	if err != nil {
		return err
	}

	if tx.DstChainId != base.ONT && tx.DstChainId != base.FLOW {
		err = s.ComposePolyHeaderProof(tx)
		if err != nil {
			return
		}
	}

	tx.MerkleValue, tx.AuditPath, _, err = s.GetPolyParams(tx)
	if err != nil {
		return err
	}

	if tx.MerkleValue.MakeTxParam == nil || !config.CONFIG.AllowMethod(tx.MerkleValue.MakeTxParam.Method) {
		method := "missing param"
		if tx.MerkleValue.MakeTxParam != nil {
			method = tx.MerkleValue.MakeTxParam.Method
		}
		return fmt.Errorf("%w Invalid poly tx, src chain(%v) tx(%s) method(%s)", msg.ERR_INVALID_TX, tx.SrcChainId, tx.PolyHash, method)
	}

	tx.SrcProxy = common.BytesToAddress(tx.MerkleValue.MakeTxParam.FromContractAddress).String()
	tx.DstProxy = common.BytesToAddress(tx.MerkleValue.MakeTxParam.ToContractAddress).String()

	if tx.DstChainId != base.ONT {
		return s.CollectSigs(tx)
	}
	return
}

func (s *Submitter) ComposePolyHeaderProof(tx *msg.Tx) (err error) {
	var anchorHeight uint32
	if tx.PolyHeight < tx.DstPolyEpochStartHeight {
		anchorHeight = tx.DstPolyEpochStartHeight + 1
	} else {
		isEpoch, _, e := s.CheckEpoch(tx, tx.PolyHeader)
		if e != nil {
			return e
		}
		if isEpoch {
			anchorHeight = tx.PolyHeight + 2
		}
	}

	if anchorHeight > 0 {
		tx.AnchorHeader, err = s.sdk.Node().GetHeaderByHeight(anchorHeight)
		if err != nil {
			return err
		}
		proof, e := s.sdk.Node().GetMerkleProof(tx.PolyHeight+1, anchorHeight)
		if e != nil {
			return e
		}
		tx.AnchorProof = proof.AuditPath
	}
	return
}

func (s *Submitter) CheckEpoch(tx *msg.Tx, hdr *types.Header) (epoch bool, pubKeys []byte, err error) {
	if tx.DstChainId == base.NEO {
		return
	}
	if len(tx.DstPolyKeepers) == 0 {
		// err = fmt.Errorf("Dst chain poly keeper not provided")
		return
	}
	if hdr.NextBookkeeper == pcom.ADDRESS_EMPTY {
		return
	}
	info := &vconf.VbftBlockInfo{}
	err = json.Unmarshal(hdr.ConsensusPayload, info)
	if err != nil {
		err = fmt.Errorf("CheckEpoch consensus payload unmarshal error %v", err)
		return
	}
	var bks []keypair.PublicKey
	for _, peer := range info.NewChainConfig.Peers {
		keyStr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keyStr)
		bks = append(bks, key)
	}
	bks = keypair.SortPublicKeys(bks)
	pubKeys = []byte{}
	sink := pcom.NewZeroCopySink(nil)
	sink.WriteUint64(uint64(len(bks)))
	for _, key := range bks {
		var bytes []byte
		bytes, err = msg.EncodePubKey(key)
		if err != nil {
			return
		}
		pubKeys = append(pubKeys, bytes...)
		bytes, err = msg.EncodeEthPubKey(key)
		if err != nil {
			return
		}
		sink.WriteVarBytes(crypto.Keccak256(bytes[1:])[12:])
	}
	epoch = !bytes.Equal(tx.DstPolyKeepers, sink.Bytes())
	return
}
