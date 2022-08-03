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
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"sync"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer/zion"
	"github.com/polynetwork/poly-relayer/store"
)

type HeaderSyncHandler struct {
	context.Context
	wg                  *sync.WaitGroup
	listener            IChainListener
	submitter           *zion.Submitter
	store               *store.Store
	height              uint64
	zionReplenishHeight uint64
	config              *config.HeaderSyncConfig
}

func NewHeaderSyncHandler(config *config.HeaderSyncConfig) *HeaderSyncHandler {
	return &HeaderSyncHandler{
		listener:  GetListener(config.ChainId),
		submitter: new(zion.Submitter),
		config:    config,
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

	h.store, err = store.NewStore(h.Chain())
	return
}

func (h *HeaderSyncHandler) start() {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := base.BlocksToWait(h.config.ChainId)
	var (
		latest uint64
		ok     bool
	)
LOOP:
	for {
		select {
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
			err = h.store.SetHeaderHeight(h.height)
			if err != nil {
				log.Error("Update header sync height height failure", "chain", h.config.ChainId, "height", h.height, "err", err)
				continue
			}

			if header != nil {
				log.Info("Header sync fetched block header", "height", h.height, "chain", h.config.ChainId)
				err = h.store.InsertHeader(h.height, hash, header)
				if err != nil {
					log.Error("Insert header failure", "chain", h.config.ChainId, "height", h.height, "err", err)
					continue
				}
			}
			continue
		}

		log.Error("Fetch block header error", "chain", h.config.ChainId, "height", h.height, "err", err)
		h.height--
	}
	log.Info("Header sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
}

func (h *HeaderSyncHandler) startReplenish() {
	h.wg.Add(1)
	defer h.wg.Done()
	srcConfirms := base.BlocksToWait(h.config.ChainId)
	zionConfirms := base.BlocksToWait(base.ZION)
	var (
		srcLatest  uint64
		zionLatest uint64
		ok         bool
	)
	for {
		select {
		case <-h.Done():
			log.Info("Header sync replenish scan is exiting now", "chain", h.config.ChainId)
			return
		default:
		}

		h.zionReplenishHeight++
		if zionLatest < h.zionReplenishHeight+zionConfirms {
			zionLatest, ok = h.submitter.SDK().WaitTillHeight(h.Context, h.zionReplenishHeight+zionConfirms, time.Duration(1)*time.Second)
		}
		if !ok {
			break
		}

		log.Debug("Scanning header sync replenish in block", "zion height", h.zionReplenishHeight, "chain", h.config.ChainId)
		opt := &bind.FilterOpts{
			Start:   h.zionReplenishHeight,
			End:     &h.zionReplenishHeight,
			Context: context.Background(),
		}
		events, err := h.submitter.SDK().Node().IInfoSync.FilterReplenishEvent(opt)
		if err == nil {
			for events.Next() {
				ev := events.Event
				if h.config.ChainId != ev.ChainID {
					continue
				}

				for _, height := range ev.Heights {
					log.Info("Header sync replenish processing block", "height", height, "chain", h.config.ChainId)

					if srcLatest < uint64(height)+srcConfirms {
						log.Warn("Skip header replenish, block not confirmed", "height", height, "chain", h.config.ChainId)
						continue
					}

					header, _, e := h.listener.Header(uint64(height))
					if e != nil {
						log.Error("Header sync replenish get header failure", "chain", h.config.ChainId, "height", height, "err", e)
						continue
					}
					if header == nil {
						log.Warn("Header sync replenish skip nil header", "chain", h.config.ChainId, "height", height)
						continue
					}

					e = h.submitter.VoteHeaderOfHeight(height, header, h.store)
					if e != nil {
						log.Error("Replenish header vote failure", "chain", h.config.ChainId, "height", height, "err", e)
						continue
					}
				}
			}
			continue
		}
		log.Error("Fetch header sync replenish events error", "chain", h.config.ChainId, "zion height", h.zionReplenishHeight, "err", err)
		h.zionReplenishHeight--
	}
}

func (h *HeaderSyncHandler) replenish() {
	zionHeight, err := h.submitter.SDK().Node().GetLatestHeight()
	if err != nil {
		log.Error("Failed to get zion latest height err ", "err", err)
		return
	}
	h.zionReplenishHeight = zionHeight
	log.Info("Header sync replenish will start...", "chain", h.config.ChainId, "zion height", h.zionReplenishHeight)

	go h.startReplenish()
	return
}

func (h *HeaderSyncHandler) Start() (err error) {
	if h.config.StartHeight != 0 {
		h.height = h.config.StartHeight
	} else {
		h.height, err = h.store.GetHeaderHeight()
		if err != nil {
			return
		}
	}

	log.Info("Header sync will start...", "height", h.height+1, "chain", h.config.ChainId)
	h.submitter.StartHeaderVote(h.Context, h.wg, h.config, h.store)
	go h.start()
	go h.replenish()
	return
}

func (h *HeaderSyncHandler) Stop() (err error) {
	return
}

func (h *HeaderSyncHandler) Chain() uint64 {
	return h.config.ChainId
}
