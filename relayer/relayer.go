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
	"sync"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/polynetwork/poly-relayer/relayer/neo"
	"github.com/polynetwork/poly-relayer/relayer/ont"
)

type IChainListener interface {
	Init(*config.ListenerConfig, *poly.SDK) error
	Defer() int
	ListenCheck() time.Duration
	ChainId() uint64
	Nodes() chains.Nodes
	Header(height uint64) (header []byte, err error)
	Scan(uint64) ([]*msg.Tx, error)
	ScanTx(string) (*msg.Tx, error)
	Compose(*msg.Tx) error
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
	Start(context.Context, *sync.WaitGroup, bus.TxBus, msg.PolyComposer) error
	Process(msg.Message, msg.PolyComposer) error
	ProcessTx(*msg.Tx, msg.PolyComposer) error
	Stop() error
}

func GetListener(chain uint64) (listener IChainListener) {
	switch chain {
	case base.ETH:
		listener = new(eth.Listener)
	case base.NEO:
		listener = new(neo.Listener)
	case base.ONT:
		listener = new(ont.Listener)
	default:
	}
	return
}

func GetSubmitter(chain uint64) (submitter IChainSubmitter) {
	switch chain {
	case base.ETH:
		submitter = new(eth.Submitter)
	default:
	}
	return
}
