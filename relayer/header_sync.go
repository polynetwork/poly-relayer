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
	"bytes"
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
	state     bus.ChainStore // sync height mark
	input     bus.ChainStore // init sync height(force)
	latest    bus.ChainStore // chain latest state
	sync      bus.ChainStore // sync state
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
	h.latest = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: h.config.ChainId, Type: bus.KEY_HEIGHT_CHAIN}, bus.New(h.config.Bus.Redis), 0,
	)
	h.sync = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: h.config.ChainId, Type: bus.KEY_HEIGHT_CHAIN_HEADER}, bus.New(h.config.Bus.Redis), 0,
	)

	return
}

func (h *HeaderSyncHandler) monitor(ch chan<- uint64) {
	timer := time.NewTicker(60 * time.Second)
	for {
		select {
		case <-h.Done():
			return
		case <-timer.C:
			switch h.config.ChainId {
			case base.BSC, base.HECO, base.MATIC, base.ETH, base.O3, base.PIXIE:
				height, err := h.submitter.GetSideChainHeight(h.config.ChainId)
				if err == nil {
					ch <- height
				}
			default:
			}
		}
	}
}

func (h *HeaderSyncHandler) RollbackToCommonAncestor(height, target uint64) uint64 {
	log.Warn("Rolling header sync back to common ancestor", "current", height, "goal", target, "chain", h.config.ChainId)
	switch h.config.ChainId {
	case base.ETH, base.HECO, base.BSC, base.O3, base.PIXIE:
	default:
		return target
	}

	var (
		a, b []byte
		err  error
	)
	for {
		// Check err here?
		b, _ = h.submitter.Poly().Node().GetSideChainHeader(h.config.ChainId, target)
		if len(b) == 0 {
			target--
			continue
		}
		_, a, err = h.listener.Header(target)
		if err == nil {
			if bytes.Equal(a, b) {
				log.Info("Found common ancestor", "chain", h.config.ChainId, "height", target)
				return target
			} else {
				target--
				continue
			}
		} else {
			log.Error("RollbackToCommonAncestor error", "chain", h.config.ChainId, "height", target)
			time.Sleep(time.Second)
		}
	}
}

func (h *HeaderSyncHandler) watch() {
	h.wg.Add(1)
	defer h.wg.Done()
	ticker := time.NewTicker(3 * time.Second)
	last := uint64(0)
	for {
		select {
		case <-h.Done():
			return
		case <-ticker.C:
			height, err := h.listener.Nodes().Node().GetLatestHeight()
			if err != nil {
				log.Error("Watch chain latest height error", "chain", h.config.ChainId, "err", err)
			} else if height > last {
				log.Info("Latest chain height", "chain", h.config.ChainId, "height", height)
				h.latest.UpdateHeight(context.Background(), height)
				last = height
			}

			switch h.config.ChainId {
			case base.BSC, base.HECO, base.MATIC, base.ETH, base.O3, base.PIXIE:
				height, err = h.submitter.GetSideChainHeight(h.config.ChainId)
				if err != nil {
					log.Error("Watch chain sync height error", "chain", h.config.ChainId, "err", err)
				} else {
					log.Info("Latest chain sync height", "chain", h.config.ChainId, "height", height)
				}
			default:
				height = 0
			}
			h.sync.UpdateHeight(context.Background(), height)
		}
	}
}

func (h *HeaderSyncHandler) start(ch chan msg.Header) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := uint64(h.listener.Defer())
	var (
		latest uint64
		ok     bool
	)
LOOP:
	for {
		select {
		case reset := <-h.reset:
			if reset < h.height && reset != 0 {
				// Drain the headers buf
			DRAIN:
				for {
					select {
					case <-ch:
					default:
						break DRAIN
					}
				}

				log.Info("Detected submit failure reset", "chain", h.config.ChainId, "value", reset)
				h.height = h.RollbackToCommonAncestor(h.height, reset-1)
			}
		case <-h.Done():
			break LOOP
		default:
		}

		h.height++
		log.Debug("Header sync processing block", "height", h.height, "chain", h.config.ChainId)
		if latest < h.height+confirms {
			latest, ok = h.listener.Nodes().WaitTillHeight(h.Context, h.height+confirms, h.listener.ListenCheck())
			if !ok {
				break LOOP
			}
		}
		header, hash, err := h.listener.Header(h.height)
		log.Debug("Header sync fetched block header", "height", h.height, "chain", h.config.ChainId, "err", err)
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
	go h.watch()
	go h.start(ch)
	return
}

func (h *HeaderSyncHandler) Stop() (err error) {
	return
}

func (h *HeaderSyncHandler) Chain() uint64 {
	return h.config.ChainId
}
