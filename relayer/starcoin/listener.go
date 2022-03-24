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

package starcoin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/chains/starcoin"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	pcom "github.com/polynetwork/poly/common"
	ccom "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/starcoinorg/starcoin-go/client"
	"strconv"
	"strings"
	"time"
)

type Listener struct {
	sdk            *starcoin.SDK
	poly           *poly.SDK
	ccm            string
	ccd            string
	config         *config.ListenerConfig
	GetProofHeight func() (uint64, error)
	GetProof       func(*client.Event, uint64) (uint64, []byte, error)
	name           string
	state          bus.ChainStore // Header sync state
}

func (l *Listener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
	if config.ChainId != base.STARCOIN {
		return fmt.Errorf("STARCOIN chain id is incorrect in config %v", config.ChainId)
	}
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.ccm = config.CCMContract
	l.poly = poly
	l.GetProofHeight = l.getProofHeight
	l.GetProof = l.getProof
	l.sdk, err = starcoin.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	l.state = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: config.ChainId, Type: bus.KEY_HEIGHT_HEADER}, bus.New(config.Bus.Redis),
		config.Bus.HeightUpdateInterval,
	)
	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	hdr, err := l.sdk.Node().HeaderWithDifficultyInfoByNumber(context.Background(), height)
	if err != nil {
		err = fmt.Errorf("starcoin HeaderWithDifficutyInfoByNumber on height %d error %v", height, err)
		return
	}
	header, err = json.Marshal(hdr)
	if err != nil {
		err = fmt.Errorf("starcoin height %d json.Marshal hdr error %v", height, err)
		return
	}
	hash, err = hdr.BlockHeader.Hash() //calculated hash
	if err != nil {
		err = fmt.Errorf("starcoin height %d get header hash  error %v", height, err)
		return
	}
	blockhash, err := hex.DecodeString(strings.TrimPrefix(hdr.BlockHeader.BlockHash, "0x"))
	if err != nil {
		err = fmt.Errorf("starcoin height %d get block hash error %v", height, err)
		return
	}
	if !bytes.Equal(hash, blockhash) {
		err = fmt.Errorf("starcoin height %d hdr.BlockHeader.Hash(): %s <> hdr.BlockHeader.BlockHash: %s", height, hex.EncodeToString(hash), hex.EncodeToString(blockhash))
		return
	}
	return
}

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	tx, err := l.sdk.Node().GetTransactionInfoByHash(context.Background(), hash)
	if err != nil {
		return 0, err
	}
	if tx == nil {
		err = fmt.Errorf("starcoin cannot get transaction info by hash %s", hash)
		return 0, err
	}
	height, err = strconv.ParseUint(tx.BlockNumber, 10, 64)
	return
}

func (l *Listener) getProofHeight() (height uint64, err error) {
	h, err := l.poly.Node().GetSideChainHeight(l.config.ChainId)
	if err != nil {
		return 0, err
	}
	height = h - base.BlocksToWait(l.config.ChainId)
	return
}

func (l *Listener) getProof(event *client.Event, txHeight uint64) (height uint64, proof []byte, err error) {
	proofHeight, err := l.GetProofHeight()
	if err != nil {
		err = fmt.Errorf("%s get proof height error %v", l.name, err)
		return
	}
	if txHeight > proofHeight {
		err = fmt.Errorf("%w Proof not ready tx height %v proof height %v", msg.ERR_PROOF_UNAVAILABLE, txHeight, height)
		// We dont return here, still fetch the proof of this tx height
		height = txHeight
	} else {
		height, err = strconv.ParseUint(event.BlockNumber, 10, 64)
	}

	txGlobalIdx, e := strconv.ParseUint(event.TransactionGlobalIndex, 10, 64)
	if e != nil {
		err = fmt.Errorf("starcoin height %d ParseUint evt.TransactionGlobalIndex error %v", txHeight, e)
		return
	}
	starcoinProof, e := l.sdk.Node().GetTransactionProof(context.Background(), event.BlockHash, txGlobalIdx, &event.EventIndex)
	if e != nil {
		err = fmt.Errorf("starcoin height %d GetTransactionProof error %v", txHeight, e)
		return
	}
	proof, e = json.Marshal(starcoinProof)
	if e != nil {
		err = fmt.Errorf("starcoin height %d Marshal srcProof error %v", txHeight, e)
		return
	}
	return
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	if tx.SrcHeight == 0 {
		return fmt.Errorf("tx missing attributes src height %v, txid %s", tx.SrcHeight, tx.TxId)
	}
	if len(tx.SrcParam) == 0 {
		return fmt.Errorf("src param is missing")
	}

	event := client.Event{}
	srcParamBytes, err := hex.DecodeString(tx.SrcParam)
	if err != nil {
		err = fmt.Errorf("starcoin height %d DecodeString tx.SrcParam error %v", tx.SrcHeight, err)
		return
	}
	err = json.Unmarshal(srcParamBytes, &event)
	if err != nil {
		err = fmt.Errorf("starcoin height %d event unmarshal error %v", tx.SrcHeight, err)
		return
	}

	eventIdx := event.EventIndex
	evtMsg := starcoin.StarcoinToPolyHeaderOrCrossChainMsg{
		EventIndex: &eventIdx,
		AccessPath: nil,
	}
	evtMsgBS, err := json.Marshal(evtMsg)
	if err != nil {
		err = fmt.Errorf("starcoin height %d marshal evtMsg error %v", tx.SrcHeight, err)
		return
	}
	tx.SrcStateRoot = evtMsgBS
	tx.SrcEvent = []byte{}

	evtData, err := hex.DecodeString(strings.TrimPrefix(event.Data, "0x"))
	if err != nil {
		err = fmt.Errorf("starcoin height %d evt.Data decodeString error %v", tx.SrcHeight, err)
		return
	}
	ccEvent, err := starcoin.DeserializeCrossChainEvent(evtData)
	if err != nil {
		err = fmt.Errorf("starcoin height %d DeserializeCrossChainDepositEvent error %v", tx.SrcHeight, err)
		return
	}
	tx.DstChainId = ccEvent.ToChainId
	tx.TxId = hex.EncodeToString(ccEvent.TxId)

	param := &ccom.MakeTxParam{}
	if err = param.Deserialization(pcom.NewZeroCopySource(ccEvent.RawData)); err != nil {
		return
	}
	tx.Param = param
	tx.SrcProofHeight, tx.SrcProof, err = l.GetProof(&event, tx.SrcHeight)
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	eventTag := "::CrossChainManager::CrossChainEvent"
	eventFilter := &client.EventFilter{
		Address:   []string{l.ccm},
		TypeTags:  []string{l.ccm + eventTag},
		FromBlock: height,
		ToBlock:   &height,
	}
	events, err := l.sdk.Node().GetEvents(context.Background(), eventFilter)
	if err != nil {
		err = fmt.Errorf("failed to fetch starcoin events height %d error %v", height, err)
		return
	}
	if events == nil {
		return
	}
	txs = []*msg.Tx{}
	for _, evt := range events {
		srcParam, e := json.Marshal(evt)
		if e != nil {
			err = fmt.Errorf("starcoin height %d json.Marshal evt error %v", height, e)
			return
		}

		tx := &msg.Tx{
			TxType:     msg.SRC,
			SrcParam:   hex.EncodeToString(srcParam),
			SrcHash:    evt.TransactionHash,
			SrcHeight:  height,
			SrcChainId: base.STARCOIN,
		}
		l.Compose(tx)
		txs = append(txs, tx)
	}
	return
}

func (l *Listener) ScanTx(string) (tx *msg.Tx, err error) {
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

func (l *Listener) Name() string {
	return l.name
}

func (l *Listener) SDK() *starcoin.SDK {
	return l.sdk
}

func (l *Listener) LatestHeight() (uint64, error) {
	return l.sdk.Node().GetLatestHeight()
}

func (l *Listener) LastHeaderSync(force, _ uint64) (height uint64, err error) {
	if l.poly == nil {
		err = fmt.Errorf("no poly sdk provided for chain %s listener", l.name)
		return
	}

	if force != 0 {
		return force, nil
	}
	return l.poly.Node().GetSideChainHeight(l.config.ChainId)
}
