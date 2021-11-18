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

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/poly"
)

type PolyEpochSyncHandler struct {
	context.Context
	wg *sync.WaitGroup

	listener *poly.Listener
	bus      bus.TxBus      // main poly tx queue
	input    bus.ChainStore // init sync height(force)
	state    bus.ChainStore
	height   uint64
	config   *config.PolyEpochSyncConfig
}

func NewPolyEpochSyncHandler(config *config.PolyEpochSyncConfig) *PolyEpochSyncHandler {
	return &PolyEpochSyncHandler{
		config:   config,
		listener: new(poly.Listener),
	}
}

func (h *PolyEpochSyncHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
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
		bus.ChainHeightKey{ChainId: h.config.ChainId, Type: bus.KEY_HEIGHT_EPOCH}, bus.New(h.config.Bus.Redis),
		h.config.Bus.HeightUpdateInterval,
	)
	h.input = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: h.config.ChainId, Type: bus.KEY_HEIGHT_EPOCH_RESET}, bus.New(h.config.Bus.Redis),
		h.config.Bus.HeightUpdateInterval,
	)

	h.bus = bus.NewRedisTxBus(bus.New(h.config.Bus.Redis), h.config.ChainId, msg.POLY)
	ok, err := bus.NewStatusLock(bus.New(h.config.Bus.Redis), bus.POLY_EPOCH_SYNC).Start(ctx, h.wg)
	if err != nil {
		return err
	}
	if !ok {
		err = fmt.Errorf("Only one poly epoch listener is expected to run.")
	}
	return
}

func (h *PolyEpochSyncHandler) Start() (err error) {
	// Reset height input
	height, err := h.input.GetHeight(context.Background())
	if err != nil {
		log.Warn("Get forced epoch sync start error, will fetch last epoch state", "err", err)
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
	log.Info("Poly epoch sync will start...", "height", h.height+1, "force", height, "last", lastHeight, "chain", h.config.ChainId)

	go h.start()
	return
}

func (h *PolyEpochSyncHandler) start() (err error) {
	h.wg.Add(1)
	defer h.wg.Done()
	var (
		latest   uint64
		ok       bool
		confirms uint64
	)
LOOP:
	for {
		select {
		case <-h.Done():
			break LOOP
		default:
		}

		h.height++
		log.Debug("Epoch sync processing block", "height", h.height, "chain", h.config.ChainId)
		if latest < h.height+confirms {
			latest, ok = h.listener.Nodes().WaitTillHeight(h.Context, h.height+confirms, h.listener.ListenCheck())
			if !ok {
				break LOOP
			}
		}
		epoch, err := h.listener.Epoch(h.height)
		log.Debug("Epoch sync fetched block header", "height", h.height, "chain", h.config.ChainId, "err", err)
		if err == nil {
			if epoch == nil {
				continue
			}
			log.Info("Found new poly epoch", "epoch", epoch.EpochId, "height", epoch.Height)
			epoch.Encode()
			tx := &msg.Tx{
				TxType:    msg.POLY_EPOCH,
				PolyEpoch: epoch,
			}
			bus.SafeCall(h.Context, tx, "push epoch change to target chain tx bus", func() error {
				return h.bus.PushToChain(context.Background(), tx)
			})
			continue
		} else {
			log.Error("Fetch poly epoch error", "chain", h.config.ChainId, "height", h.height, "err", err)
		}
		h.height--
	}
	log.Info("Epoch sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
	return
}

func (h *PolyEpochSyncHandler) Stop() (err error) {
	return
}

func (h *PolyEpochSyncHandler) Chain() uint64 {
	return h.config.ChainId
}
