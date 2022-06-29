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

type TxVoteHandler struct {
	context.Context
	wg        *sync.WaitGroup
	listener  IChainListener
	submitter *zion.Submitter
	height    uint64
	config    *config.TxVoteConfig
	store     *store.Store
}

func NewTxVoteHandler(config *config.TxVoteConfig) *TxVoteHandler {
	return &TxVoteHandler{
		listener:  GetListener(config.ChainId),
		submitter: new(zion.Submitter),
		config:    config,
	}
}

func (h *TxVoteHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
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

func (h *TxVoteHandler) start() (err error) {
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
			log.Info("Src tx vote handler is exiting...", "chain", h.config.ChainId, "height", h.height)
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
			var list []*store.Tx
			for _, tx := range txs {
				log.Info("Found src tx", "hash", tx.SrcHash, "chain", h.config.ChainId, "height", h.height)
				list = append(list, store.NewTx(tx))
			}
			err = h.store.InsertTxs(list)
			if err == nil {
				err = h.store.SetTxHeight(h.height)
				if err != nil {
					log.Error("Update tx vote height failure", "chain", h.config.ChainId, "height", h.height, "err", err)
				}
				continue
			}
		}

		log.Error("Fetch block txs failure", "chain", h.config.ChainId, "height", h.height, "err", err)
		h.height--
	}
}

func (h *TxVoteHandler) Start() (err error) {
	h.height, err = h.store.GetTxHeight()
	if err != nil {
		return
	}
	log.Info("Tx vote will start...", "height", h.height+1, "chain", h.config.ChainId)
	h.submitter.StartTxVote(h.Context, h.wg, h.config, h.store)
	go h.start()
	return
}

func (h *TxVoteHandler) Stop() (err error) {
	return
}

func (h *TxVoteHandler) Chain() uint64 {
	return h.config.ChainId
}
