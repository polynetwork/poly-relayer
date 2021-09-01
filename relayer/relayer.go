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

	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type IChainListener interface {
	Init(*config.ListenerConfig, *poly.SDK) error
	Defer() int
	ListenCheck() time.Duration
	ChainId() uint64
	Nodes() chains.Nodes
	Header(height uint64) (header []byte, err error)
	Scan(uint64) ([]*msg.Tx, error)
	ScanTx(string) error
}

type Handler interface {
	Init(context.Context, *sync.WaitGroup) error
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
