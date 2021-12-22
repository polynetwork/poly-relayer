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

type EpochSyncHandler struct {
	context.Context
	wg *sync.WaitGroup

	listener  *poly.Listener
	submitter IChainSubmitter
	epoch     uint64
	config    *config.EpochSyncConfig
}

func NewEpochSyncHandler(config *config.EpochSyncConfig) *EpochSyncHandler {
	return &EpochSyncHandler{
		config:    config,
		listener:  new(poly.Listener),
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

	err = h.submitter.Init(h.config.SubmitterConfig)
	if err != nil {
		return
	}
	return
}

func (h *EpochSyncHandler) Start() (err error) {
	go h.run()
	return
}

func (h *EpochSyncHandler) run() (err error) {
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

		h.epoch, err = h.submitter.GetPolyEpochId()
		if err != nil {
			log.Error("Failed to fetch cur epoch id", "chain", h.config.ChainId)
			continue
		}
		epochs, err := h.listener.EpochUpdate(h.Context, h.epoch)
		if err != nil {
			log.Error("Failed to fetch epoch update", "chain", h.config.ChainId)
			continue
		}

		for _, epoch := range epochs {
			tx := &msg.Tx{
				TxType:     msg.POLY_EPOCH,
				PolyEpoch:  epoch,
				DstChainId: h.config.ChainId,
			}
			bus.Retry(h.Context, func() error {
				err = h.submitter.ProcessEpoch(tx)
				if err != nil {
					log.Error("Failed to submit epoch change", "chain", h.config.ChainId, "epoch", epoch.EpochId, "height", epoch.Height, "err", err)
				}
				return err
			}, time.Second, 0)
		}
	}
	log.Info("Epoch sync handler is exiting...", "chain", h.config.ChainId, "epoch", h.epoch)
	return nil
}
func (h *EpochSyncHandler) start() (err error) {
	/*
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
	   				TxType:     msg.POLY_EPOCH,
	   				PolyEpoch:  epoch,
	   				DstChainId: h.config.ChainId,
	   			}
	   			bus.SafeCall(h.Context, tx, "push epoch change to target chain tx bus", func() error {
	   				return h.bus.PushToChains(context.Background(), tx, base.CHAINS)
	   			})
	   			continue
	   		} else {
	   			log.Error("Fetch poly epoch error", "chain", h.config.ChainId, "height", h.height, "err", err)
	   		}
	   		h.height--
	   	}
	   	log.Info("Epoch sync handler is exiting...", "chain", h.config.ChainId, "height", h.height)
	*/
	return
}

func (h *EpochSyncHandler) Stop() (err error) {
	return
}

func (h *EpochSyncHandler) Chain() uint64 {
	return h.config.ChainId
}
