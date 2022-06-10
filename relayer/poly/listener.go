/*
 * Copyright (C) 2021 The poly network Authors
 * This file is part of The poly network library.
 *
 * The  poly network  is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The  poly network  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with The poly network .  If not, see <http://www.gnu.org/licenses/>.
 */

package poly

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/onflow/cadence/runtime"
	"github.com/onflow/flow-go/crypto/hash"
	flowcrypto "github.com/onflow/flow-go/fvm/crypto"
	"github.com/polynetwork/bridge-common/chains/flow"
	"time"

	ecom "github.com/ethereum/go-ethereum/common"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	pcom "github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/native/service/cross_chain_manager/common"
)

type Listener struct {
	sdk    *poly.SDK
	config *config.ListenerConfig
}

func (l *Listener) Init(config *config.ListenerConfig, sdk *poly.SDK) (err error) {
	l.config = config
	if sdk != nil {
		l.sdk = sdk
	} else {
		l.sdk, err = poly.WithOptions(base.POLY, config.Nodes, time.Minute, 1)
	}
	return
}

func (l *Listener) ScanDst(height uint64) (txs []*msg.Tx, err error) {
	txs, err = l.Scan(height)
	if err != nil {
		return
	}
	sub := &Submitter{sdk: l.sdk}
	for _, tx := range txs {
		tx.MerkleValue, _, _, err = sub.GetProof(tx.PolyHeight, tx.PolyKey)
		if err != nil {
			return
		}
	}
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	events, err := l.sdk.Node().GetSmartContractEventByBlock(uint32(height))
	if err != nil {
		return nil, err
	}

	for _, event := range events {
		for _, notify := range event.Notify {
			states := notify.States.([]interface{})
			var tx *msg.Tx
			switch notify.ContractAddress {
			case poly.CCM_ADDRESS:
				if len(states) < 6 {
					continue
				}
				tx, err = l.parseCcmNotifyStates(event.TxHash, states)
			case poly.SM_ADDRESS:
				if len(states) < 4 {
					continue
				}
				tx, err = l.parseSmNotifyStates(height, event.TxHash, states)
			default:
				continue
			}
			if err != nil {
				return nil, err
			}
			if tx != nil {
				txs = append(txs, tx)
			}
		}
	}

	return
}

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	h, err := l.sdk.Node().GetBlockHeightByTxHash(hash)
	height = uint64(h)
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	//hash hasn't '0x'
	event, err := l.sdk.Node().GetSmartContractEvent(hash)
	if err != nil {
		return nil, err
	}
	for _, notify := range event.Notify {
		states := notify.States.([]interface{})
		switch notify.ContractAddress {
		case poly.CCM_ADDRESS:
			if len(states) < 6 {
				continue
			}
			tx, err = l.parseCcmNotifyStates(event.TxHash, states)
		case poly.SM_ADDRESS:
			if len(states) < 4 {
				continue
			}
			if polyHeight, e := l.sdk.Node().GetBlockHeightByTxHash(hash); e != nil {
				return nil, e
			} else {
				tx, err = l.parseSmNotifyStates(uint64(polyHeight), event.TxHash, states)
			}
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		if tx != nil {
			return tx, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("hash:%v hasn't event", hash))
}

func (l *Listener) ChainId() uint64 {
	return base.POLY
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	return
}

func (l *Listener) Defer() int {
	return 1
}

func (l *Listener) Header(uint64) (header []byte, hash []byte, err error) {
	return
}

func (l *Listener) ListenCheck() time.Duration {
	duration := time.Second
	if l.config.ListenCheck > 0 {
		duration = time.Duration(l.config.ListenCheck) * time.Second
	}
	return duration
}

func (l *Listener) Nodes() chains.Nodes {
	return l.sdk.ChainSDK
}

func (l *Listener) LastHeaderSync(uint64, uint64) (uint64, error) {
	return 0, nil
}

func (l *Listener) LatestHeight() (uint64, error) {
	return l.sdk.Node().GetLatestHeight()
}

func (l *Listener) Validate(tx *msg.Tx) (err error) {
	t, err := l.ScanTx(tx.PolyHash)
	if err != nil {
		return
	}
	if t == nil {
		return msg.ERR_TX_PROOF_MISSING
	}
	if tx.SrcChainId != t.SrcChainId {
		return fmt.Errorf("%w SrcChainID does not match: %v, was %v", msg.ERR_TX_VOILATION, tx.SrcChainId, t.SrcChainId)
	}
	if tx.DstChainId != t.DstChainId {
		return fmt.Errorf("%w DstChainID does not match: %v, was %v", msg.ERR_TX_VOILATION, tx.DstChainId, t.DstChainId)
	}
	sub := &Submitter{sdk: l.sdk}
	value, _, _, err := sub.GetProof(t.PolyHeight, t.PolyKey)
	if err != nil {
		return
	}
	if value == nil {
		return msg.ERR_TX_PROOF_MISSING
	}
	a := util.LowerHex(hex.EncodeToString(value.MakeTxParam.ToContractAddress))
	b := util.LowerHex(tx.DstProxy)
	if a != b {
		return fmt.Errorf("%w ToContract does not match: %v, was %v", msg.ERR_TX_VOILATION, b, a)
	}
	return
}

func (l *Listener) SDK() *poly.SDK {
	return l.sdk
}

func (l *Listener) parseCcmNotifyStates(txHash string, states []interface{}) (tx *msg.Tx, err error) {
	method, _ := states[0].(string)
	if method != "makeProof" {
		return
	}
	dstChain := uint64(states[2].(float64))
	if dstChain == 0 {
		err = fmt.Errorf("Invalid dst chain id in poly tx, txHash=%s ", txHash)
		log.Error("parseMakeProofStates", "error", err)
		return
	}

	if dstChain == base.FLOW {
		return
	}

	tx = new(msg.Tx)
	tx.DstChainId = dstChain
	tx.PolyKey = states[5].(string)
	tx.PolyHeight = uint32(states[4].(float64))
	tx.PolyHash = txHash
	tx.TxType = msg.POLY
	tx.TxId = states[3].(string)
	tx.SrcChainId = uint64(states[1].(float64))
	switch tx.SrcChainId {
	case base.NEO, base.NEO3, base.ONT:
		tx.TxId = util.ReverseHex(tx.TxId)
	}
	return
}

func (l *Listener) parseSmNotifyStates(height uint64, txHash string, states []interface{}) (tx *msg.Tx, err error) {
	method, _ := states[0].(string)
	if method != "AddSignatureQuorum" {
		return
	}
	log.Info("found flow AddSignatureQuorum event", "height", height, "txHash", txHash)
	dstChain := uint64(states[3].(float64))
	if dstChain == 0 {
		err = fmt.Errorf("txHash=%s invalid dst chain id", txHash)
		log.Error("parseAddSignatureQuorumStates", "error", err)
		return
	}

	sigKey, err := base64.StdEncoding.DecodeString(states[1].(string))
	if err != nil {
		err = fmt.Errorf("txHash=%s decode sig error=%s", txHash, err)
		log.Error("parseAddSignatureQuorumStates", "error", err)
		return
	}

	sigStorage, err := l.sdk.Node().GetStorage(poly.SM_ADDRESS, append([]byte("sigInfo"), sigKey...))
	if err != nil {
		err = fmt.Errorf("txHash=%s get sigInfo error=%s", txHash, err)
		log.Error("failed to GetStorage", "error", err)
	}

	subject, err := base64.StdEncoding.DecodeString(states[2].(string))
	if err != nil {
		err = fmt.Errorf("txHash=%s decode subject error=%s", txHash, err)
		log.Error("parseAddSignatureQuorumStates", "error", err)
		return
	}

	sigInfo := new(poly.SigInfo)
	err = sigInfo.Deserialization(pcom.NewZeroCopySource(sigStorage))
	if err != nil {
		err = fmt.Errorf("txHash=%s deserialization sigRawData error=%s", txHash, err)
		log.Error("parseAddSignatureQuorumStates", "error", err)
		return
	}

	toMerkleValue := &common.ToMerkleValue{}
	subjectValueZS := pcom.NewZeroCopySource(subject)
	if err = toMerkleValue.Deserialization(subjectValueZS); err != nil {
		err = fmt.Errorf("txHash=%s deserialization subject error=%s", txHash, err)
		log.Error("parseAddSignatureQuorumStates", "error", err)
		return
	}

	tx = new(msg.Tx)
	tx.DstChainId = dstChain
	tx.PolyHeight = uint32(height)
	tx.PolyHash = txHash
	tx.TxType = msg.POLY
	tx.Subject = subject
	tx.SigStorage = sigStorage

	tx.SrcChainId = toMerkleValue.FromChainID
	tx.MerkleValue = toMerkleValue
	tx.TxId = ecom.BytesToAddress(toMerkleValue.MakeTxParam.TxHash).String()

	if dstChain == base.FLOW {
		tag := "FLOW-V0.0-user"
		var hasher hash.Hasher
		hasher, err = flowcrypto.NewPrefixedHashing(flowcrypto.RuntimeToCryptoHashingAlgorithm(runtime.HashAlgorithmSHA2_256), tag)
		if err != nil {
			err = fmt.Errorf("create SHA2_256 hasher for the prefix tag %s error %s", tag, err)
			log.Error("parseAddSignatureQuorumStates", "error", err)
		}

		sigs, signers := make([][]byte, 0), make([][]byte, 0)
		for k, sig := range sigInfo.SigInfo {
			sigs = append(sigs, sig)
			var polyAddr pcom.Address
			polyAddr, err = pcom.AddressFromBase58(k)
			if err != nil {
				fmt.Println(err)
			}
			h := hasher.ComputeHash(subject)
			var flowPub []byte
			flowPub, err = flow.RecoverPubkeyFromFlowSig(h[:], sig, polyAddr)
			if err != nil {
				err = fmt.Errorf("txHash=%s recover pubkey from flow sig error=%s", txHash, err)
				log.Error("parseAddSignatureQuorumStates", "error", err)
			}
			signers = append(signers, flowPub)
		}
		tx.Sigs = sigs
		tx.Signers = signers

		args := new(flow.Args)
		err = args.Deserialization(pcom.NewZeroCopySource(toMerkleValue.MakeTxParam.Args))
		if err != nil {
			err = fmt.Errorf("txHash=%s deserialization args error=%s", txHash, err)
			log.Error("parseAddSignatureQuorumStates", "error", err)
			return
		}
		resourceRoute := new(flow.ResourceRoute)
		err = resourceRoute.Deserialization(pcom.NewZeroCopySource(args.ToAddress))
		if err != nil {
			err = fmt.Errorf("txHash=%s deserialization args.ToAddress error=%s", txHash, err)
			log.Error("parseAddSignatureQuorumStates", "error", err)
			return
		}
		tx.ResourcePath = resourceRoute.Path
	}

	return
}
