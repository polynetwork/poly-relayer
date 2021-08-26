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

package eth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	// "github.com/beego/beego/v2/core/logs"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/eth"
	"github.com/polynetwork/bridge-common/chains/poly"
	ceth "github.com/polynetwork/poly/native/service/cross_chain_manager/eth"

	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	pcom "github.com/polynetwork/poly/common"
	ccom "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
)

type Listener struct {
	sdk            *eth.SDK
	poly           *poly.SDK
	ccm            common.Address
	ccd            common.Address
	config         *config.ListenerConfig
	GetProofHeight func() (uint64, error)
	GetProof       func([]byte) ([]byte, error)
	name           string
}

func (l *Listener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.ccm = common.HexToAddress(config.CCMContract)
	l.ccd = common.HexToAddress(config.CCDContract)
	l.poly = poly
	// Common
	l.GetProofHeight = l.getProofHeight
	l.GetProof = l.getProof

	l.sdk, err = eth.NewSDK(config.ChainId, config.Nodes, time.Minute, 1)
	return
}

func (l *Listener) getProofHeight() (height uint64, err error) {
	switch l.config.ChainId {
	case base.ETH, base.BSC, base.HECO, base.O3:
		h, err := l.poly.Node().GetSideChainHeight(l.config.ChainId)
		if err != nil {
			return 0, err
		}
		height = h - uint64(l.config.Defer)
	case base.OK:
		h, err := l.sdk.Node().GetLatestHeight()
		if err != nil {
			return 0, err
		}
		height = h - 3
	default:
		return 0, fmt.Errorf("getProofHeight unsupported chain %s", l.name)
	}
	return
}

func (l *Listener) getProof(txId []byte) (proof []byte, err error) {
	id := msg.EncodeTxId(txId)
	bytes, err := ceth.MappingKeyAt(id, "01")
	if err != nil {
		err = fmt.Errorf("%s scan event mapping key error %v", l.name, err)
		return
	}
	proofKey := hexutil.Encode(bytes)
	height, err := l.GetProofHeight()
	if err != nil {
		err = fmt.Errorf("%s can height get proof height error %v", l.name, err)
		return
	}
	ethProof, err := l.sdk.Node().GetProof(l.ccd.String(), proofKey, height)
	if err != nil {
		return nil, err
	}
	proof, err = json.Marshal(ethProof)
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	ccm, err := eccm_abi.NewEthCrossChainManager(l.ccm, l.sdk.Node())
	if err != nil {
		return nil, err
	}
	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}
	events, err := ccm.FilterCrossChainEvent(opt, nil)
	if err != nil {
		return nil, err
	}

	if events == nil {
		return
	}

	txs = []*msg.Tx{}
	for events.Next() {
		ev := events.Event
		param := &ccom.MakeTxParam{}
		err = param.Deserialization(pcom.NewZeroCopySource([]byte(ev.Rawdata)))
		if err != nil {
			return
		}
		tx := &msg.Tx{
			TxId:       msg.EncodeTxId(ev.TxId),
			SrcHash:    ev.Raw.TxHash.String(),
			DstChainId: ev.ToChainId,
			SrcEvent:   hex.EncodeToString(ev.Rawdata),
			SrcHeight:  height,
		}
		//TODO: Add filters here?
		proof, err := l.GetProof(ev.TxId)
		if err != nil {
			return nil, err
		}
		tx.SrcProof = hex.EncodeToString(proof)
		txs = append(txs, tx)
	}

	return
}

func (l *Listener) ScanTx(hash string) (err error) {
	return
}
