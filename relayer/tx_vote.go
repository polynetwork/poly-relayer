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
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer/zion"
	"github.com/polynetwork/poly-relayer/store"
	"sync"
	"time"
)

type TxVoteHandler struct {
	context.Context
	wg                  *sync.WaitGroup
	listener            IChainListener
	submitter           *zion.Submitter
	height              uint64
	zionReplenishHeight uint64
	config              *config.TxVoteConfig
	store               *store.Store
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

func (h *TxVoteHandler) startReplenish() {
	h.wg.Add(1)
	defer h.wg.Done()
	srcConfirms := base.BlocksToWait(h.config.ChainId)
	zionConfirms := base.BlocksToWait(base.ZION)
	var (
		zionLatestHeight uint64
		ok               bool
	)
	for {
		select {
		case <-h.Done():
			log.Info("Tx vote replenish scan is exiting now", "chain", h.config.ChainId)
			return
		default:
		}

		h.zionReplenishHeight++
		if zionLatestHeight < h.zionReplenishHeight+zionConfirms {
			zionLatestHeight, ok = h.submitter.SDK().WaitTillHeight(h.Context, h.zionReplenishHeight+zionConfirms, time.Duration(1)*time.Second)
		}
		if !ok {
			break
		}

		log.Info("Scanning tx vote replenish in block", "zion height", h.zionReplenishHeight, "chain", h.config.ChainId)
		opt := &bind.FilterOpts{
			Start:   h.zionReplenishHeight,
			End:     &h.zionReplenishHeight,
			Context: context.Background(),
		}
		events, err := h.submitter.SDK().Node().ICrossChainManager.FilterReplenishEvent(opt)
		if err == nil {
			for events.Next() {
				ev := events.Event
				if h.config.ChainId != ev.ChainID {
					continue
				}

				srcLatestHeight, e := h.listener.LatestHeight()
				if err != nil {
					log.Error("Get LatestHeight failed", "chain", h.config.ChainId, "err", e)
					continue
				}

				for _, hash := range ev.TxHashes {
					height, e := h.listener.GetTxBlock(hash)
					if e != nil {
						log.Error("Tx vote replenish get tx block failure", "chain", h.config.ChainId, "hash", hash, "err", e)
						continue
					}
					if srcLatestHeight < height+srcConfirms {
						log.Warn("Skip tx vote replenish, block not confirmed", "src hash", hash, "height", height, "chain", h.config.ChainId)
						continue
					}

					tx, e := h.listener.ScanTx(hash)
					if e != nil {
						log.Error("Tx vote replenish scan tx failure", "chain", h.config.ChainId, "hash", hash, "err", e)
						continue
					}

					e = h.submitter.VoteTxOfHash(tx, h.store)
					if e != nil {
						log.Error("Replenish tx vote failure", "chain", h.config.ChainId, "height", height, "hash", hash, "err", e)
						continue
					}
				}
			}
			continue
		}
		log.Error("Fetch tx vote replenish events error", "chain", h.config.ChainId, "zion height", h.zionReplenishHeight, "err", err)
		h.zionReplenishHeight--
	}
}

func (h *TxVoteHandler) replenish() {
	zionHeight, err := h.submitter.SDK().Node().GetLatestHeight()
	if err != nil {
		log.Error("Failed to get zion latest height err ", "err", err)
		return
	}
	h.zionReplenishHeight = zionHeight
	log.Info("Tx vote replenish will start...", "chain", h.config.ChainId, "zion height", h.zionReplenishHeight)

	go h.startReplenish()
	return
}

func (h *TxVoteHandler) Start() (err error) {
	h.height, err = h.store.GetTxHeight()
	if err != nil {
		return
	}
	log.Info("Tx vote will start...", "height", h.height+1, "chain", h.config.ChainId)
	h.submitter.StartTxVote(h.Context, h.wg, h.config, h.store)
	go h.start()
	go h.replenish()
	return
}

func (h *TxVoteHandler) Stop() (err error) {
	return
}

func (h *TxVoteHandler) Chain() uint64 {
	return h.config.ChainId
}
