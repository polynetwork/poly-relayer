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

package neo

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/joeqian10/neo-gogogo/block"
	"github.com/joeqian10/neo-gogogo/helper"
	"github.com/joeqian10/neo-gogogo/helper/io"
	"github.com/joeqian10/neo-gogogo/mpt"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/neo"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/poly/common"
	scom "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	hsneo "github.com/polynetwork/poly/native/service/header_sync/neo"

	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Listener struct {
	sdk       *neo.SDK
	poly      *poly.SDK
	ccm       string
	ccd       string
	config    *config.ListenerConfig
	consensus string // NEO consensus state
	name      string
}

func (l *Listener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
	if config.ChainId != base.NEO {
		return fmt.Errorf("NEO chain id is incorrect in config %v", config.ChainId)
	}
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.ccm = util.LowerHex(config.CCMContract)
	l.ccd = util.LowerHex(config.CCDContract)
	l.poly = poly
	l.sdk, err = neo.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	return
}

func (l *Listener) getProofHeight(txHeight uint64) (height uint64, err error) {
	h, err := l.poly.Node().GetSideChainHeight(l.config.ChainId)
	if err != nil {
		return 0, fmt.Errorf("getProofHeight unsupported chain %s err %v", l.name, err)
	}
	if txHeight >= h {
		height = txHeight
	} else {
		height = h
	}
	return
}

func verifyFromNeoTx(proof []byte, crosschainMsg *hsneo.NeoCrossChainMsg) (*scom.MakeTxParam, error) {
	crossStateProofRoot, err := helper.UInt256FromString(crosschainMsg.StateRoot.StateRoot)
	if err != nil {
		return nil, fmt.Errorf("verifyFromNeoTx, decode cross state proof root from string error: %s", err)
	}

	scriptHash, key, proofs, err := mpt.ResolveProof(proof)
	if err != nil {
		return nil, fmt.Errorf("VerifyNeoCrossChainProof, neo-gogogo mpt.ResolveProof error: %v", err)
	}
	value, err := mpt.VerifyProof(crossStateProofRoot.Bytes(), scriptHash, key, proofs)
	if err != nil {
		return nil, fmt.Errorf("VerifyNeoCrossChainProof, neo-gogogo mpt.VerifyProof error: %v", err)
	}

	source := common.NewZeroCopySource(value)
	txParam := new(scom.MakeTxParam)
	if err := txParam.Deserialization(source); err != nil {
		return nil, fmt.Errorf("VerifyFromNeoTx, deserialize merkleValue error: %s", err)
	}
	return txParam, nil
}

func (l *Listener) ParseParam(tx *msg.Tx) (err error) {
	crossChainMsg := new(hsneo.NeoCrossChainMsg)
	err = crossChainMsg.Deserialization(common.NewZeroCopySource(tx.SrcStateRoot))
	if err != nil {
		err = fmt.Errorf("neo MakeDepositProposal, deserialize crossChainMsg error: %v", err)
		return
	}

	param, err := verifyFromNeoTx(tx.SrcProof, crossChainMsg)
	if err != nil {
		err = fmt.Errorf("neo MakeDepositProposal, deserialize crossChainMsg error: %v", err)
		return
	}
	tx.Param = param
	return
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	res := l.sdk.Node().GetStateHeight()
	if res.HasError() {
		err = fmt.Errorf("Get neo state height error #{res.Error.Message}")
		return
	}
	tx.SrcProofHeight = uint64(res.Result.StateHeight)
	if tx.SrcProofHeight < tx.SrcHeight || tx.SrcHeight == 0 || tx.SrcProofHeight == 0 {
		err = fmt.Errorf("Proof not available yet %d tx height %d", tx.SrcProofHeight, tx.SrcHeight)
		return
	}
	sr := l.sdk.Node().GetStateRootByIndex(uint32(tx.SrcProofHeight))
	if sr.HasError() {
		err = fmt.Errorf("Get state root failure for neo, height %d #{sr.Error.Message}", tx.SrcProofHeight)
		return
	}
	root := sr.Result.StateRoot
	buf := io.NewBufBinaryWriter()
	root.Serialize(buf.BinaryWriter)
	tx.SrcStateRoot = buf.Bytes()

	pf := l.sdk.Node().GetProof(root.StateRoot, "0x"+helper.ReverseString(l.ccm), tx.TxId)
	if pf.HasError() {
		err = fmt.Errorf("Get proof error for neo #{pf.Error.Message}")
		return
	}
	tx.SrcProof, err = hex.DecodeString(pf.CrosschainProof.Proof)
	if err != nil {
		err = fmt.Errorf("Decode src proof error %v", err)
		return
	}
	err = l.ParseParam(tx)
	return
}

func (l *Listener) fetchLastConsensus() (height uint64, err error) {

	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	res := l.sdk.Node().GetBlockHeaderByIndex(uint32(height))
	if res.HasError() {
		return nil, nil, fmt.Errorf("Fetch block header error #{response.Error.Message}")
	}
	if res.Result.NextConsensus == l.consensus {
		return nil, nil, nil
	}
	// Assuming success relayer here?
	l.consensus = res.Result.NextConsensus
	h, err := block.NewBlockHeaderFromRPC(&res.Result)
	if err != nil {
		return nil, nil, err
	}
	buf := io.NewBufBinaryWriter()
	h.Serialize(buf.BinaryWriter)
	return buf.Bytes(), nil, nil
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	res := l.sdk.Node().GetBlockByIndex(uint32(height))
	if res.HasError() {
		err = fmt.Errorf("Failed to fetch block for chain %s height %d error %v", l.name, height, res.Error.Message)
		return
	}
	if res.Result.Hash == "" {
		err = fmt.Errorf("Failed to fetch block for chain %s height %d error not available", l.name, height)
		return
	}

	// TODO: use more threads here
	// size := len(res.Result.Tx)
	txs = []*msg.Tx{}
	for _, t := range res.Result.Tx {
		if t.Type != "InvocationTransaction" {
			continue
		}
		tx, err := l.scanTx(t.Txid, height)
		if err != nil {
			return nil, err
		}
		if tx != nil {
			txs = append(txs, tx)
		}
	}
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	return
}

func (l *Listener) scanTx(hash string, height uint64) (tx *msg.Tx, err error) {
	res := l.sdk.Node().GetApplicationLog(hash)
	if res.HasError() {
		return nil, fmt.Errorf("Failed to fetch app log for tx %s error %v", hash, res.Error.Message)
	}
	for _, exec := range res.Result.Executions {
		if exec.VMState == "FAULT" {
			return
		}
		for _, noti := range exec.Notifications {
			u, _ := helper.UInt160FromString(noti.Contract)
			if helper.BytesToHex(u.Bytes()) == l.ccm {
				if noti.State.Type != "Array" {
					err = fmt.Errorf("Invalid type desires Array, got %s", noti.State.Type)
					return
				}
				states := noti.State.Value
				method, _ := hex.DecodeString(states[0].Value)
				if string(method) != "CrossChainLockEvent" {
					continue
				}
				if len(states) != 6 {
					err = fmt.Errorf("Tx exec notification expect length of 6, but got %v", len(states))
					return
				}

				var toChainId *big.Int
				if states[3].Type == "Integer" {
					toChainId, _ = new(big.Int).SetString(states[3].Value, 10)
				} else {
					toChainId, _ = new(big.Int).SetString(util.ReverseHex(states[3].Value), 16)
				}

				tx := &msg.Tx{
					TxId:       states[4].Value, // hexstring for storeKey: 0102 + toChainId + toRequestId, like 01020501
					SrcHash:    hash,
					SrcHeight:  height,
					SrcChainId: l.config.ChainId,
				}

				if toChainId != nil {
					tx.DstChainId = toChainId.Uint64()
				}
				return tx, nil
			}
		}
	}
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

func (l *Listener) ChainId() uint64 {
	return l.config.ChainId
}

func (l *Listener) Defer() int {
	return l.config.Defer
}

func (l *Listener) LastHeaderSync(force, last uint64) (height uint64, err error) {
	if l.poly == nil {
		err = fmt.Errorf("No poly sdk provided for NEO FetchLastConsensus")
		return
	}
	height, err = l.poly.Node().GetSideChainHeight(l.config.ChainId)
	if err != nil {
		return
	}
	if last > height {
		height = last
	}

	res := l.sdk.Node().GetBlockHeaderByIndex(uint32(height))
	if res.HasError() {
		return 0, fmt.Errorf("Fetch block header error #{response.Error.Message}")
	}
	l.consensus = res.Result.NextConsensus

	if force != 0 {
		return force, nil
	}
	return
}
