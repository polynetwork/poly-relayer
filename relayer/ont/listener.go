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

package ont

import (
	"encoding/json"
	"fmt"
	"time"

	outils "github.com/ontio/ontology/smartcontract/service/native/utils"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"

	"github.com/polynetwork/bridge-common/chains/ont"
	"github.com/polynetwork/bridge-common/chains/poly"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"

	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Listener struct {
	sdk    *ont.SDK
	poly   *poly.SDK
	ccm    string
	ccd    string
	config *config.ListenerConfig
	name   string
}

func (l *Listener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
	if config.ChainId != base.ONT {
		return fmt.Errorf("ONT chain id is incorrect in config %v", config.ChainId)
	}
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.ccm = outils.CrossChainContractAddress.ToHexString()
	l.poly = poly
	if poly == nil {
		return fmt.Errorf("Poly sdk instance should be provided for the listener of %s", l.name)
	}

	l.sdk = ont.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
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
	block, err := l.sdk.Node().GetBlockByHeight(uint32(height))
	if err != nil {
		return
	}
	info := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(block.Header.ConsensusPayload, info); err != nil {
		return nil, fmt.Errorf("ONT unmarshal blockInfo error: %s", err)
	}
	if info.NewChainConfig != nil {
		return block.Header.ToArray(), nil
	}
	return nil, nil
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	events, err := l.sdk.Node().GetSmartContractEventByBlock(uint32(height))
	if err != nil {
		return nil, fmt.Errorf("ONT failed to fetch smart contract events for height %d, err %v", height, err)
	}
	txs = []*msg.Tx{}
	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress != l.ccm {
				continue
			}
			states, ok := notify.States.([]interface{})
			if !ok || states[0].(string) != "makeFromOntProof" {
				continue
			}
			tx := &msg.Tx{
				TxId:       states[4].(string),
				SrcHeight:  height,
				SrcChainId: base.ONT,
				SrcHash:    event.TxHash,
				DstChainId: uint64(states[2].(float64)),
			}
			txs = append(txs, tx)
		}
	}
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	return
}

func (l *Listener) scanTx(hash string, height uint64) (tx *msg.Tx, err error) {
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
