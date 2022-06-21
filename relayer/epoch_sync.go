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
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/zion"
)

type EpochSyncHandler struct {
	context.Context
	wg *sync.WaitGroup

	listener         *zion.Listener
	submitter        IChainSubmitter
	epochStartHeight uint64
	config           *config.EpochSyncConfig
	name             string
}

func NewEpochSyncHandler(config *config.EpochSyncConfig) *EpochSyncHandler {
	return &EpochSyncHandler{
		config:    config,
		listener:  new(zion.Listener),
		submitter: GetSubmitter(config.ChainId),
	}
}

func (h *EpochSyncHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg

	if h.listener == nil {
		return fmt.Errorf("Unabled to create listener for chain %s", base.GetChainName(h.config.Listener.ChainId))
	}
	err = h.listener.Init(h.config.Listener, nil)
	if err != nil {
		return
	}

	if h.submitter == nil {
		return fmt.Errorf("Unabled to create submitter for chain %s", base.GetChainName(h.config.ChainId))
	}

	h.name = fmt.Sprintf("%s->%s", base.GetChainName(h.config.Listener.ChainId), base.GetChainName(h.config.ChainId))
	err = h.submitter.Init(h.config.SubmitterConfig)
	if err != nil {
		return
	}
	return
}

func (h *EpochSyncHandler) Start() (err error) {
	go h.start()
	return
}

func (h *EpochSyncHandler) start() (err error) {
	ticker := time.NewTicker(time.Second)
	h.wg.Add(1)
	defer h.wg.Done()
LOOP:
	for {
		select {
		case <-ticker.C:
		case <-h.Done():
			break LOOP
		}

		h.epochStartHeight, err = h.submitter.GetPolyEpochStartHeight(h.config.Listener.ChainId)
		if err != nil {
			log.Error("Failed to fetch cur epoch start height", "chain", h.name)
			continue
		}
		epochs, err := h.listener.EpochUpdate(h.Context, h.epochStartHeight)
		if err != nil {
			log.Error("Failed to fetch epoch update", "chain", h.name)
			continue
		}

		txs := []*msg.Tx{}
		for _, epoch := range epochs {
			txs = append(txs, &msg.Tx{
				TxType:     msg.POLY_EPOCH,
				PolyEpoch:  epoch,
				DstChainId: h.config.ChainId,
			})
		}
		h.submitter.ProcessEpochs(txs)
		if err != nil {
			log.Error("Failed to submit epoch change", "chain", h.name, "size", len(txs), "epoch", h.epochStartHeight, "err", err)
		}
	}
	log.Info("Epoch sync handler is exiting...", "chain", h.name, "epoch", h.epochStartHeight)
	return nil
}

func (h *EpochSyncHandler) Stop() (err error) {
	return
}

func (h *EpochSyncHandler) Chain() uint64 {
	return h.config.ChainId
}
