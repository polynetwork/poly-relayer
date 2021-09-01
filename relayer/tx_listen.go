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

	"github.com/beego/beego/v2/core/logs"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
)

type SrcTxSyncHandler struct {
	context.Context
	wg *sync.WaitGroup

	listener IChainListener
	bus      bus.TxBus
	state    bus.ChainStore
	height   uint64
	config   *config.SrcTxSyncConfig
}

func NewSrcTxSyncHandler(config *config.SrcTxSyncConfig, listener IChainListener) *SrcTxSyncHandler {
	return &SrcTxSyncHandler{
		config:   config,
		listener: listener,
	}
}

func (h *SrcTxSyncHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg
	return
}

func (h *SrcTxSyncHandler) Start() (err error) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := uint64(h.listener.Defer())
	var latest uint64
	for {
		select {
		case <-h.Done():
			logs.Info("Src tx sync handler(chain %v height %v) is exiting...", h.config.ChainId, h.height)
			break
		default:
		}

		h.height++
		if latest < h.height+confirms {
			latest = h.listener.Nodes().WaitTillHeight(h.height+confirms, h.listener.ListenCheck())
		}
		txs, err := h.listener.Scan(h.height)
		if err == nil {
			for _, tx := range txs {
				// TODO: do reliable push here
				err = h.bus.Push(context.Background(), tx)
			}
			h.state.HeightMark(h.height)
			continue
		} else {
			logs.Error("Fetch chain(%v) block %v  header error %v", h.config.ChainId, h.height, err)
		}
		h.height--
	}
	return
}

func (h *SrcTxSyncHandler) Stop() (err error) {
	return
}

type PolyTxSyncHandler struct {
	context.Context
	wg *sync.WaitGroup

	listener IChainListener
	bus      bus.TxBus
	state    bus.ChainStore
	height   uint64
	config   *config.PolyTxSyncConfig
}

func NewPolyTxSyncHandler(config *config.PolyTxSyncConfig, listener IChainListener) *PolyTxSyncHandler {
	return &PolyTxSyncHandler{
		config:   config,
		listener: listener,
	}
}

func (h *PolyTxSyncHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg
	return
}

func (h *PolyTxSyncHandler) Start() (err error) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := uint64(h.listener.Defer())
	var latest uint64
	for {
		select {
		case <-h.Done():
			logs.Info("Src tx sync handler(chain %v height %v) is exiting...", h.config.ChainId, h.height)
			break
		default:
		}

		h.height++
		if latest < h.height+confirms {
			latest = h.listener.Nodes().WaitTillHeight(h.height+confirms, h.listener.ListenCheck())
		}
		txs, err := h.listener.Scan(h.height)
		if err == nil {
			for _, tx := range txs {
				// TODO: do reliable push here
				err = h.bus.PushToChain(context.Background(), tx)
			}
			h.state.HeightMark(h.height)
			continue
		} else {
			logs.Error("Fetch chain(%v) block %v  header error %v", h.config.ChainId, h.height, err)
		}
		h.height--
	}
	return
}

func (h *PolyTxSyncHandler) Stop() (err error) {
	return
}
