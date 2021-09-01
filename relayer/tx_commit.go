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
	"github.com/polynetwork/poly-relayer/relayer/poly"
)

type PolyTxCommitHandler struct {
	context.Context
	wg *sync.WaitGroup

	bus       bus.TxBus
	submitter IChainSubmitter
	composer  *poly.Submitter
	config    *config.PolyTxCommitConfig
}

func (h *PolyTxCommitHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg
	return
}

func (h *PolyTxCommitHandler) Start() (err error) {
	err = h.submitter.Start(h.Context, h.wg, h.bus, h.composer.ComposeTx)
	return
}

func (h *PolyTxCommitHandler) Stop() (err error) {
	return
}

type SrcTxCommitHandler struct {
	context.Context
	wg *sync.WaitGroup

	bus       bus.TxBus
	submitter *poly.Submitter
	config    *config.PolyTxCommitConfig
}

func (h *SrcTxCommitHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg
	return
}

func (h *SrcTxCommitHandler) Start() (err error) {
	err = h.submitter.Start(h.Context, h.wg, h.bus)
	return
}

func (h *SrcTxCommitHandler) Stop() (err error) {
	return
}
