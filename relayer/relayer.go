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

	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type ChainListener interface {
	Init(*config.ListenerConfig) error
	Scan(uint64) error
	ScanTx(string) error
}

type IListener interface {
	Init(*config.ListenerConfig, chan msg.Message) error
	Start(context.Context, *sync.WaitGroup) error
	Stop() error
}

type IChainSubmitter interface {
	Init(*config.SubmitterConfig) error
	Submit(msg.Message) error
	Hook(context.Context, *sync.WaitGroup, <-chan msg.Message) error
	Start(context.Context, *sync.WaitGroup, bus.TxBus) error
	Process(msg.Message, msg.PolyComposer) error
	Stop() error
}
