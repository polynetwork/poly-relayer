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
	"github.com/polynetwork/poly-relayer/relayer/poly"
)

type HeaderSyncHandler struct {
	context.Context
	wg        *sync.WaitGroup
	listener  IChainListener
	submitter *poly.Submitter
	state     bus.ChainStore
	height    uint64
	config    *config.HeaderSyncConfig
}

func NewHeaderSyncHandler(config *config.HeaderSyncConfig, listener IChainListener, submitter *poly.Submitter) *HeaderSyncHandler {
	return &HeaderSyncHandler{
		listener:  listener,
		submitter: submitter,
		config:    config,
	}
}

func (h *HeaderSyncHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg
	return
}

func (h *HeaderSyncHandler) start(ch chan<- []byte) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := uint64(h.listener.Defer())
	var latest uint64
	for {
		select {
		case <-h.Done():
			logs.Info("Header sync handler(chain %v height %v) is exiting...", h.config.ChainId, h.height)
			close(ch)
			break
		default:
		}

		h.height++
		if latest < h.height+confirms {
			latest = h.listener.Nodes().WaitTillHeight(h.height+confirms, h.listener.ListenCheck())
		}
		header, err := h.listener.Header(h.height)
		if err == nil {
			ch <- header
			h.state.HeightMark(h.height)
			continue
		} else {
			logs.Error("Fetch chain(%v) block %v  header error %v", h.config.ChainId, h.height, err)
		}
		h.height--
	}
}

func (h *HeaderSyncHandler) Start() (err error) {
	h.height, err = h.state.GetHeight(context.Background())
	if err != nil {
		return
	}
	ch, err := h.submitter.StartSync(h.Context, h.wg, h.config)
	if err != nil {
		return
	}
	go h.start(ch)
	return
}

func (h *HeaderSyncHandler) Stop() (err error) {
	return
}

func (h *HeaderSyncHandler) Chain() uint64 {
	return h.config.ChainId
}
