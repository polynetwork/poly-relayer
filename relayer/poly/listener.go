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
	"context"
	"encoding/hex"
	"fmt"
	"time"

	zcom "github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"
	ccm "github.com/devfans/zion-sdk/contracts/native/go_abi/cross_chain_manager_abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	pcom "github.com/polynetwork/poly/common"
)

type Listener struct {
	sdk    *zion.SDK
	config *config.ListenerConfig
}

func (l *Listener) Init(config *config.ListenerConfig, sdk *zion.SDK) (err error) {
	l.config = config
	if sdk != nil {
		l.sdk = sdk
	} else {
		l.sdk, err = zion.WithOptions(base.POLY, config.Nodes, time.Minute, 1)
	}
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	ccm, err := ccm.NewCrossChainManager(zion.CCM_ADDRESS, l.sdk.Node())
	if err != nil {
		return nil, err
	}
	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}
	events, err := ccm.FilterMakeProof(opt)
	if err != nil {
		return nil, err
	}

	if events == nil {
		return
	}

	txs = []*msg.Tx{}
	for events.Next() {
		ev := events.Event
		param := new(zcom.ToMerkleValue)
		value, err := hex.DecodeString(ev.MerkleValueHex)
		if err != nil {
			return nil, err
		}
		err = param.Deserialization(pcom.NewZeroCopySource(value))
		if err != nil {
			err = fmt.Errorf("GetPolyParams: param.Deserialization error %v", err)
			return nil, err
		}

		tx := new(msg.Tx)
		tx.MerkleValue = param
		tx.DstChainId = param.MakeTxParam.ToChainID
		tx.SrcProxy = hex.EncodeToString(param.MakeTxParam.FromContractAddress)
		tx.DstProxy = hex.EncodeToString(param.MakeTxParam.ToContractAddress)
		tx.PolyKey = ev.Key
		tx.PolyHeight = height
		tx.PolyHash = ev.Raw.TxHash
		tx.TxType = msg.POLY
		tx.TxId = hex.EncodeToString(param.MakeTxParam.CrossChainID)
		tx.SrcChainId = param.FromChainID
		/*
			switch tx.SrcChainId {
			case base.NEO, base.ONT:
				tx.TxId = util.ReverseHex(tx.TxId)
			}
		*/
		txs = append(txs, tx)
	}

	return
}

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	h, err := l.sdk.Node().GetBlockHeightByTxHash(msg.Hash(hash))
	height = uint64(h)
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	return
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
