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
	patch    bus.TxBus
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
	h.patch = bus.NewRedisPatchTxBus(bus.New(h.config.Bus.Redis), h.config.ChainId)
	return
}

func (h *SrcTxSyncHandler) Start() (err error) {
	h.height, err = h.state.GetHeight(context.Background())
	if err != nil {
		return
	}

	go h.start()
	go h.patchTxs()
	return
}

func (h *SrcTxSyncHandler) patchTxs() {
	h.wg.Add(1)
	defer h.wg.Done()
	for {
		select {
		case <-h.Done():
			log.Info("Src tx patch handler is exiting...", "chain", h.config.ChainId)
			return
		default:
		}

		tx, err := h.patch.Pop(h.Context)
		if err != nil {
			log.Error("Bus pop error", "err", err, "chain", h.config.ChainId)
			continue
		}
		if tx == nil {
			log.Warn("Bus pop nil?", "chain", h.config.ChainId)
			time.Sleep(time.Second)
			continue
		}
		log.Info("Received patch tx request", "tx", tx.Encode())

		height := tx.SrcHeight
		if height == 0 && tx.SrcHash != "" {
			height, err = h.listener.GetTxBlock(tx.SrcHash)
			if err != nil {
				log.Error("Failed to get tx block", "hash", tx.SrcHash, "chain", h.config.ChainId)
				continue
			}
		}

		if height == 0 {
			log.Error("Failed to patch tx for height is invalid", "chain", h.config.ChainId, "body", tx.Encode())
			continue
		}

		txs, err := h.listener.Scan(height)
		if err != nil {
			log.Error("Fetch block txs error", "chain", h.config.ChainId, "height", height, "err", err)
		}

		for _, t := range txs {
			if tx.SrcHash == "" || tx.SrcHash == t.SrcHash {
				log.Info("Found patch target src tx", "hash", t.SrcHash, "chain", h.config.ChainId, "height", height)
				bus.SafeCall(h.Context, t, "push to tx bus", func() error {
					return h.bus.Push(context.Background(), t)
				})
			} else {
				log.Info("Found src tx in block", "hash", t.SrcHash, "chain", h.config.ChainId, "height", height)
			}
		}
	}
}

func (h *SrcTxSyncHandler) start() (err error) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := base.BlocksToWait(h.config.ChainId)
	var (
		latest uint64
		ok     bool
	)
	for {
		select {
		case <-h.Done():
			log.Info("Src tx sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
			return nil
		default:
		}

		h.height++
		if latest < h.height+confirms {
			latest, ok = h.listener.Nodes().WaitTillHeight(h.Context, h.height+confirms, h.listener.ListenCheck())
			if !ok {
				continue
			}
		}
		log.Info("Scanning txs in block", "height", h.height, "chain", h.config.ChainId)
		txs, err := h.listener.Scan(h.height)
		if err == nil {
			for _, tx := range txs {
				log.Info("Found src tx", "hash", tx.SrcHash, "chain", h.config.ChainId, "height", h.height)
				bus.SafeCall(h.Context, tx, "push to tx bus", func() error {
					return h.bus.Push(context.Background(), tx)
				})
			}
			h.state.HeightMark(h.height)
			continue
		} else {
			log.Error("Fetch block txs error", "chain", h.config.ChainId, "height", h.height, "err", err)
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
	bus      bus.TxBus        // main poly tx queue
	patch    bus.TxBus        // path poly tx queue
	queue    bus.DelayedTxBus // delayed poly tx queue
	state    bus.ChainStore
	skip     bus.SkipCheck
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
	h.patch = bus.NewRedisPatchTxBus(bus.New(h.config.Bus.Redis), base.POLY)
	h.queue = bus.NewRedisDelayedTxBus(bus.New(h.config.Bus.Redis))
	h.skip = bus.NewRedisSkipCheck(bus.New(h.config.Bus.Redis))
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
	go h.checkDelayed()
	go h.patchTxs()
	return
}

func (h *PolyTxSyncHandler) start() (err error) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := uint64(h.listener.Defer())
	var (
		latest uint64
		ok     bool
	)
	for {
		select {
		case <-h.Done():
			log.Info("Poly tx sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
			return nil
		default:
		}

		h.height++
		if latest < h.height+confirms {
			latest, ok = h.listener.Nodes().WaitTillHeight(h.Context, h.height+confirms, h.listener.ListenCheck())
			if !ok {
				continue
			}
		}
		log.Info("Scanning poly txs in block", "height", h.height, "chain", h.config.ChainId)
		txs, err := h.listener.Scan(h.height)
		if err == nil {
			for _, tx := range txs {
				log.Info("Found poly tx", "hash", tx.PolyHash)
				bus.SafeCall(h.Context, tx, "push to target chain tx bus", func() error {
					return h.bus.PushToChain(context.Background(), tx)
				})
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

func (h *PolyTxSyncHandler) checkDelayed() (err error) {
	h.wg.Add(1)
	defer h.wg.Done()
	for {
		select {
		case <-h.Done():
			log.Info("Delayed poly tx sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
			return nil
		default:
		}

		tx, score, err := h.queue.Pop(h.Context)
		if err != nil {
			log.Error("Deplayed poly tx queue pop error", "err", err)
			continue
		}
		if tx != nil && score > 0 {
			skip, _ := h.skip.CheckSkip(h.Context, tx)
			if skip {
				log.Warn("Skipping tx for marked to skip", "poly_hash", tx.PolyHash)
				continue
			}
			if score <= time.Now().Unix() {
				bus.SafeCall(h.Context, tx, "push to delay queue", func() error {
					log.Info("Pushing back delayed tx for not active yet", "chain", tx.DstChainId, "poly_hash", tx.PolyHash)
					return h.bus.PushToChain(context.Background(), tx)
				})
				continue
			} else {
				bus.SafeCall(h.Context, tx, "push to delay queue", func() error {
					return h.queue.Delay(context.Background(), tx, score)
				})
			}
		}
		select {
		case <-h.Done():
			log.Info("Delayed poly tx sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
			return nil
		case <-time.After(time.Second):
		}
	}
}

func (h *PolyTxSyncHandler) patchTxs() {
	h.wg.Add(1)
	defer h.wg.Done()
	for {
		select {
		case <-h.Done():
			log.Info("Poly tx patch handler is exiting...", "chain", h.config.ChainId)
			return
		default:
		}

		tx, err := h.patch.Pop(h.Context)
		if err != nil {
			log.Error("Bus pop error", "err", err, "chain", h.config.ChainId)
			continue
		}
		if tx == nil {
			log.Warn("Bus pop nil?", "chain", h.config.ChainId)
			time.Sleep(time.Second)
			continue
		}

		log.Info("Received patch tx request", "tx", tx.Encode())
		height := uint64(tx.PolyHeight)
		if height == 0 && tx.PolyHash != "" {
			height, err = h.listener.GetTxBlock(tx.PolyHash)
			if err != nil {
				log.Error("Failed to get poly tx block", "hash", tx.PolyHash, "chain", h.config.ChainId)
				continue
			}
		}

		if height == 0 {
			log.Error("Failed to patch poly tx for height is invalid", "chain", h.config.ChainId, "body", tx.Encode())
			continue
		}

		txs, err := h.listener.Scan(height)
		if err != nil {
			log.Error("Fetch poly block txs error", "chain", h.config.ChainId, "height", height, "err", err)
		}

		for _, t := range txs {
			if tx.PolyHash == "" || tx.PolyHash == t.PolyHash {
				log.Info("Found patch target poly tx", "hash", t.PolyHash, "chain", h.config.ChainId, "height", height)
				bus.SafeCall(h.Context, t, "push to target chain tx bus", func() error {
					return h.bus.PushToChain(context.Background(), t)
				})
			} else {
				log.Info("Found poly tx in block", "hash", t.PolyHash, "chain", h.config.ChainId, "height", height)
			}
		}
	}
}

func (h *PolyTxSyncHandler) Stop() (err error) {
	return
}

func (h *PolyTxSyncHandler) Chain() uint64 {
	return h.config.ChainId
}
