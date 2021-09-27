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
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
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

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	events, err := l.sdk.Node().GetSmartContractEventByBlock(uint32(height))
	if err != nil {
		return nil, err
	}

	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress == poly.CCM_ADDRESS {
				states := notify.States.([]interface{})
				if len(states) < 6 {
					continue
				}
				method, _ := states[0].(string)
				if method != "makeProof" {
					continue
				}

				dstChain := uint64(states[2].(float64))
				if dstChain == 0 {
					log.Error("Invalid dst chain id in poly tx", "hash", event.TxHash)
					continue
				}

				tx := new(msg.Tx)
				tx.DstChainId = dstChain
				tx.PolyKey = states[5].(string)
				tx.PolyHeight = uint32(height)
				tx.PolyHash = event.TxHash
				tx.TxType = msg.POLY
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
