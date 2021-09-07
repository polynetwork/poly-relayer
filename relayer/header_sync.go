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

	"github.com/beego/beego/v2/core/logs"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
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
	reset     chan uint64
}

func NewHeaderSyncHandler(config *config.HeaderSyncConfig) *HeaderSyncHandler {
	return &HeaderSyncHandler{
		listener:  GetListener(config.ChainId),
		submitter: new(poly.Submitter),
		config:    config,
		reset:     make(chan uint64, 1),
	}
}

func (h *HeaderSyncHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	switch h.config.ChainId {
	case base.OK, base.MATIC:
		return fmt.Errorf("Please use dedicated build for header sync of chains: OK, MATIC")
	}

	h.Context = ctx
	h.wg = wg

	err = h.submitter.Init(h.config.Poly)
	if err != nil {
		return
	}

	err = h.listener.Init(h.config.ListenerConfig, h.submitter.SDK())
	if err != nil {
		return
	}

	h.state = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: h.config.ChainId, Type: bus.KEY_HEIGHT_HEADER}, bus.New(h.config.Bus.Redis),
		h.config.Bus.HeightUpdateInterval,
	)
	return
}

func (h *HeaderSyncHandler) monitor(ch chan<- uint64) {
	timer := time.NewTicker(120 * time.Second)
	for {
		select {
		case <-h.Done():
			return
		case <-timer.C:
			height, err := h.submitter.GetSideChainHeight(h.config.ChainId)
			if err == nil {
				ch <- height
			}
		}
	}
}

func (h *HeaderSyncHandler) start(ch chan<- msg.Header) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := uint64(h.listener.Defer())
	feedback := make(chan uint64, 1)
	go h.monitor(feedback)
	var latest uint64
	for {
		select {
		case height := <-feedback:
			if height != 0 && height < h.height-uint64(2*h.config.Batch) {
				logs.Info("Resetting side chain(%d) header sync with feedback to height %d from %d", h.config.ChainId, height, h.height)
				h.height = height - 1
			}
		case reset := <-h.reset:
			if reset < h.height && reset != 0 {
				logs.Info("Resetting side chain(%d) header sync to height %d", h.config.ChainId, reset)
				h.height = reset - 1
			}
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
		header, hash, err := h.listener.Header(h.height)
		if err == nil {
			if header != nil {
				ch <- msg.Header{Data: header, Height: h.height, Hash: hash}
			}
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
	ch, err := h.submitter.StartSync(h.Context, h.wg, h.config, h.reset)
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
