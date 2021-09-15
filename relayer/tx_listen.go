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

func NewSrcTxSyncHandler(config *config.SrcTxSyncConfig) *SrcTxSyncHandler {
	return &SrcTxSyncHandler{
		config:   config,
		listener: GetListener(config.ChainId),
	}
}

func (h *SrcTxSyncHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg

	if h.listener == nil {
		return fmt.Errorf("Unabled to create listener for chain %s", base.GetChainName(h.config.ChainId))
	}

	err = h.listener.Init(h.config.ListenerConfig, nil)
	if err != nil {
		return
	}

	h.state = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: h.config.ChainId, Type: bus.KEY_HEIGHT_TX}, bus.New(h.config.Bus.Redis),
		h.config.Bus.HeightUpdateInterval,
	)

	h.bus = bus.NewRedisTxBus(bus.New(h.config.Bus.Redis), h.config.ChainId, msg.SRC)
	return
}

func (h *SrcTxSyncHandler) Start() (err error) {
	h.height, err = h.state.GetHeight(context.Background())
	if err != nil {
		return
	}

	go h.start()
	return
}

func (h *SrcTxSyncHandler) start() (err error) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := base.BlocksToWait(h.config.ChainId)
	var latest uint64
	for {
		select {
		case <-h.Done():
			log.Info("Src tx sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
			return nil
		default:
		}

		h.height++
		if latest < h.height+confirms {
			latest = h.listener.Nodes().WaitTillHeight(h.height+confirms, h.listener.ListenCheck())
		}
		log.Info("Scanning txs in block", "height", h.height, "chain", h.config.ChainId)
		txs, err := h.listener.Scan(h.height)
		if err == nil {
			for _, tx := range txs {
				log.Info("Found src tx", "hash", tx.SrcHash, "chain", h.config.ChainId)
				retry(func() error { return h.bus.Push(context.Background(), tx) }, time.Second)
			}
			h.state.HeightMark(h.height)
			continue
		} else {
			log.Error("Fetch block header error", "chain", h.config.ChainId, "height", h.height, "err", err)
		}
		h.height--
	}
	return
}

func (h *SrcTxSyncHandler) Stop() (err error) {
	return
}

func (h *SrcTxSyncHandler) Chain() uint64 {
	return h.config.ChainId
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

func NewPolyTxSyncHandler(config *config.PolyTxSyncConfig) *PolyTxSyncHandler {
	return &PolyTxSyncHandler{
		config:   config,
		listener: GetListener(config.ChainId),
	}
}

func (h *PolyTxSyncHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg
	if h.listener == nil {
		return fmt.Errorf("Unabled to create listener for chain %s", base.GetChainName(h.config.ChainId))
	}
	err = h.listener.Init(h.config.ListenerConfig, nil)
	if err != nil {
		return
	}

	h.state = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: h.config.ChainId, Type: bus.KEY_HEIGHT_TX}, bus.New(h.config.Bus.Redis),
		h.config.Bus.HeightUpdateInterval,
	)

	h.bus = bus.NewRedisTxBus(bus.New(h.config.Bus.Redis), h.config.ChainId, msg.POLY)
	ok, err := bus.NewStatusLock(bus.New(h.config.Bus.Redis), bus.POLY_SYNC).Start(ctx, h.wg)
	if err != nil {
		return err
	}
	if !ok {
		err = fmt.Errorf("Only one poly tx listener is expected to run.")
	}
	return
}

func (h *PolyTxSyncHandler) Start() (err error) {
	h.height, err = h.state.GetHeight(context.Background())
	if err != nil {
		return
	}

	go h.start()
	return
}

func (h *PolyTxSyncHandler) start() (err error) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := uint64(h.listener.Defer())
	var latest uint64
	for {
		select {
		case <-h.Done():
			log.Info("Src tx sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
			return nil
		default:
		}

		h.height++
		if latest < h.height+confirms {
			latest = h.listener.Nodes().WaitTillHeight(h.height+confirms, h.listener.ListenCheck())
		}
		log.Info("Scanning poly txs in block", "height", h.height, "chain", h.config.ChainId)
		txs, err := h.listener.Scan(h.height)
		if err == nil {
			for _, tx := range txs {
				log.Info("Found poly tx", "hash", tx.PolyHash)
				retry(func() error {
					return h.bus.PushToChain(context.Background(), tx)
				}, time.Second)
			}
			h.state.HeightMark(h.height)
			continue
		} else {
			log.Error("Fetch block header error", "chain", h.config.ChainId, "height", h.height, "err", err)
		}
		h.height--
	}
	return
}

func (h *PolyTxSyncHandler) Stop() (err error) {
	return
}

func (h *PolyTxSyncHandler) Chain() uint64 {
	return h.config.ChainId
}
