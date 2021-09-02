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

func NewPolyTxCommitHandler(config *config.PolyTxCommitConfig) *PolyTxCommitHandler {
	return &PolyTxCommitHandler{
		config:    config,
		submitter: GetSubmitter(config.ChainId),
		composer:  new(poly.Submitter),
	}
}

func (h *PolyTxCommitHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg

	err = h.submitter.Init(h.config.SubmitterConfig)
	if err != nil {
		return
	}

	err = h.composer.Init(h.config.Poly)
	if err != nil {
		return
	}

	h.bus = bus.NewRedisTxBus(bus.New(h.config.Bus.Redis), h.config.ChainId, msg.POLY)
	return
}

func (h *PolyTxCommitHandler) Start() (err error) {
	err = h.submitter.Start(h.Context, h.wg, h.bus, h.composer.ComposeTx)
	return
}

func (h *PolyTxCommitHandler) Stop() (err error) {
	return
}

func (h *PolyTxCommitHandler) Chain() uint64 {
	return h.config.ChainId
}

type SrcTxCommitHandler struct {
	context.Context
	wg *sync.WaitGroup

	bus       bus.TxBus
	submitter *poly.Submitter
	listener  IChainListener
	config    *config.SrcTxCommitConfig
}

func NewSrcTxCommitHandler(config *config.SrcTxCommitConfig) *SrcTxCommitHandler {
	return &SrcTxCommitHandler{
		config:    config,
		submitter: new(poly.Submitter),
		listener:  GetListener(config.ChainId),
	}
}

func (h *SrcTxCommitHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg

	err = h.submitter.Init(h.config.Poly)
	if err != nil {
		return
	}

	h.bus = bus.NewRedisTxBus(bus.New(h.config.Bus.Redis), h.config.ChainId, msg.SRC)
	err = h.listener.Init(h.config.ListenerConfig, nil)
	return
}

func (h *SrcTxCommitHandler) Start() (err error) {
	err = h.submitter.Start(h.Context, h.wg, h.bus, h.listener.Compose)
	return
}

func (h *SrcTxCommitHandler) Stop() (err error) {
	return
}

func (h *SrcTxCommitHandler) Chain() uint64 {
	return h.config.ChainId
}
