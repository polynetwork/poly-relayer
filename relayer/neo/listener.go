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
	"fmt"
	"math/big"
	"time"

	"github.com/joeqian10/neo-gogogo/block"
	"github.com/joeqian10/neo-gogogo/helper"
	"github.com/joeqian10/neo-gogogo/helper/io"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/neo"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/util"

	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Listener struct {
	sdk    *neo.SDK
	poly   *poly.SDK
	ccm    string
	ccd    string
	config *config.ListenerConfig
	name   string
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
	if poly == nil {
		return fmt.Errorf("Poly sdk instance should be provided for the listener of %s", l.name)
	}

	l.sdk = neo.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
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

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	return
}

func (l *Listener) Header(height uint64) (header []byte, err error) {
	res := l.sdk.Node().GetBlockHeaderByIndex(uint32(height))
	if res.HasError() {
		return nil, fmt.Errorf("Fetch block header error #{response.Error.Message}")
	}
	h, err := block.NewBlockHeaderFromRPC(&res.Result)
	if err != nil {
		return nil, err
	}
	buf := io.NewBufBinaryWriter()
	h.Serialize(buf.BinaryWriter)
	return buf.Bytes(), nil
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
				if states[0].Value != "43726f7373436861696e4c6f636b4576656e74" { // "CrossChainLockEvent"
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
					TxId:      states[4].Value, // hexstring for storeKey: 0102 + toChainId + toRequestId, like 01020501
					SrcHash:   hash,
					SrcHeight: height,
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
