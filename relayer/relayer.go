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

package relayer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/bridge"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/polynetwork/poly-relayer/relayer/matic"
	"github.com/polynetwork/poly-relayer/relayer/neo"
	"github.com/polynetwork/poly-relayer/relayer/ok"
	"github.com/polynetwork/poly-relayer/relayer/ont"
	po "github.com/polynetwork/poly-relayer/relayer/poly"
)

type IChainListener interface {
	Init(*config.ListenerConfig, *poly.SDK) error
	Defer() int
	ListenCheck() time.Duration
	ChainId() uint64
	Nodes() chains.Nodes
	Header(height uint64) (header []byte, hash []byte, err error)
	LastHeaderSync(uint64, uint64) (uint64, error)
	Scan(uint64) ([]*msg.Tx, error)
	ScanTx(string) (*msg.Tx, error)
	GetTxBlock(string) (uint64, error)
	Compose(*msg.Tx) error
	LatestHeight() (uint64, error)
}

type Handler interface {
	Init(context.Context, *sync.WaitGroup) error
	Chain() uint64
	Start() error
	Stop() error
}

type IChainSubmitter interface {
	Init(*config.SubmitterConfig) error
	Submit(msg.Message) error
	Hook(context.Context, *sync.WaitGroup, <-chan msg.Message) error
	Start(context.Context, *sync.WaitGroup, bus.TxBus, bus.DelayedTxBus, msg.PolyComposer) error
	Process(msg.Message, msg.PolyComposer) error
	ProcessTx(*msg.Tx, msg.PolyComposer) error
	Stop() error
}

func GetListener(chain uint64) (listener IChainListener) {
	switch chain {
	case base.ETH, base.BSC, base.HECO, base.O3:
		listener = new(eth.Listener)
	case base.OK:
		listener = new(ok.Listener)
	case base.MATIC:
		listener = new(matic.Listener)
	case base.NEO:
		listener = new(neo.Listener)
	case base.ONT:
		listener = new(ont.Listener)
	case base.POLY:
		listener = new(po.Listener)
	default:
	}
	return
}

func GetSubmitter(chain uint64) (submitter IChainSubmitter) {
	switch chain {
	case base.ETH, base.BSC, base.HECO, base.O3, base.ARBITRUM, base.XDAI, base.OPTIMISM, base.FANTOM, base.AVA, base.METIS, base.RINKEBY, base.BOBA, base.PIXIE:
		submitter = new(eth.Submitter)
	case base.NEO:
		submitter = new(neo.Submitter)
	case base.ONT:
		submitter = new(ont.Submitter)
	default:
	}
	return
}

func PolySubmitter() (sub *po.Submitter, err error) {
	sub = new(po.Submitter)
	err = sub.Init(&config.CONFIG.Poly.PolySubmitterConfig)
	return
}

func PolyListener() (l *po.Listener, err error) {
	l = new(po.Listener)
	err = l.Init(config.CONFIG.Poly.PolyTxSync.ListenerConfig, nil)
	return
}

func ChainSubmitter(chain uint64) (sub IChainSubmitter, err error) {
	sub = GetSubmitter(chain)
	if sub == nil {
		err = fmt.Errorf("No submitter for chain %d available", chain)
		return
	}
	conf := config.CONFIG.Chains[chain]
	if conf == nil || conf.PolyTxCommit == nil {
		return nil, fmt.Errorf("No config available for submitter of chain %d", chain)
	}
	err = sub.Init(conf.PolyTxCommit.SubmitterConfig)
	return
}

func ChainListener(chain uint64, poly *poly.SDK) (l IChainListener, err error) {
	l = GetListener(chain)
	if l == nil {
		err = fmt.Errorf("No listener for chain %d available", chain)
		return
	}
	conf := config.CONFIG.Chains[chain]
	if conf == nil || conf.SrcTxSync == nil {
		return nil, fmt.Errorf("No config available for listener of chain %d", chain)
	}

	err = l.Init(conf.SrcTxSync.ListenerConfig, poly)
	return
}

func Bridge() (sdk *bridge.SDK, err error) {
	return bridge.WithOptions(0, config.CONFIG.Bridge, time.Minute, 100)
}
