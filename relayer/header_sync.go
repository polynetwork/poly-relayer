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
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer/zion"
	"github.com/polynetwork/poly-relayer/store"
)

type HeaderSyncHandler struct {
	context.Context
	wg        *sync.WaitGroup
	listener  IChainListener
	submitter *zion.Submitter
	store     *store.Store
	height    uint64
	config    *config.HeaderSyncConfig
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
			if header == nil {
				continue
			}
			err = h.store.InsertHeader(h.height, hash, header)
			if err == nil {
				err = h.store.SetHeaderHeight(h.height)
				if err != nil {
					log.Error("Update tx vote height failure", "chain", h.config.ChainId, "height", h.height, "err", err)
				}
				continue
			}
		}

		log.Error("Fetch block header error", "chain", h.config.ChainId, "height", h.height, "err", err)
		h.height--
	}
	log.Info("Header sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
}

func (h *HeaderSyncHandler) Start() (err error) {
	h.height, err = h.store.GetHeaderHeight()
	if err != nil {
		return
	}
	log.Info("Header sync will start...", "height", h.height+1, "chain", h.config.ChainId)
	h.submitter.StartHeaderVote(h.Context, h.wg, h.config, h.store)
	go h.start()
	return
}

func (h *HeaderSyncHandler) Stop() (err error) {
	return
}

func (h *HeaderSyncHandler) Chain() uint64 {
	return h.config.ChainId
}
