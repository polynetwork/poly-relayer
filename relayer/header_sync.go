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
	"github.com/polynetwork/bridge-common/log"
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
	input     bus.ChainStore
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
	h.Context = ctx
	h.wg = wg

	err = h.submitter.Init(h.config.Poly)
	if err != nil {
		return
	}

	if h.listener == nil {
		return fmt.Errorf("Unabled to create listener for chain %s", base.GetChainName(h.config.ChainId))
	}

	err = h.listener.Init(h.config.ListenerConfig, h.submitter.SDK())
	if err != nil {
		return
	}

	h.state = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: h.config.ChainId, Type: bus.KEY_HEIGHT_HEADER}, bus.New(h.config.Bus.Redis),
		h.config.Bus.HeightUpdateInterval,
	)
	h.input = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: h.config.ChainId, Type: bus.KEY_HEIGHT_HEADER_RESET}, bus.New(h.config.Bus.Redis),
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
			switch h.config.ChainId {
			case base.ONT, base.NEO, base.HEIMDALL, base.OK:
			default:
				height, err := h.submitter.GetSideChainHeight(h.config.ChainId)
				if err == nil {
					ch <- height
				}
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
LOOP:
	for {
		select {
		case height := <-feedback:
			if height != 0 && height < h.height-uint64(2*h.config.Batch) {
				log.Info("Resetting side header sync with feedback", "chain", h.config.ChainId, "to", height, "from", h.height)
				h.height = height - 1
			}
		case reset := <-h.reset:
			if reset < h.height && reset != 0 {
				log.Info("Resetting side chain header sync", "chain", h.config.ChainId, "to", reset)
				h.height = reset - 1
			}
		case <-h.Done():
			break LOOP
		default:
		}

		h.height++
		if latest < h.height+confirms {
			latest = h.listener.Nodes().WaitTillHeight(h.height+confirms, h.listener.ListenCheck())
		}
		header, hash, err := h.listener.Header(h.height)
		if err == nil {
			select {
			case ch <- msg.Header{Data: header, Height: h.height, Hash: hash}:
			case <-h.Done():
				break LOOP
			}
			continue
		} else {
			log.Error("Fetch block header error", "chain", h.config.ChainId, "height", h.height, "err", err)
		}
		h.height--
	}
	log.Info("Header sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
	close(ch)
}

func (h *HeaderSyncHandler) Start() (err error) {
	// Reset height input
	height, err := h.input.GetHeight(context.Background())
	if err != nil {
		log.Warn("Get forced header sync start error, will fetch last header state", "err", err)
	} else {
		// Attempt to clear reset
		h.input.UpdateHeight(context.Background(), 0)
	}
	// Last successful sync height
	lastHeight, _ := h.state.GetHeight(context.Background())
	h.height, err = h.listener.LastHeaderSync(height, lastHeight)
	if err != nil {
		return
	}
	log.Info("Header sync will start...", "height", h.height+1, "force", height, "last", lastHeight, "chain", h.config.ChainId)
	ch, err := h.submitter.StartSync(h.Context, h.wg, h.config, h.reset, h.state)
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
