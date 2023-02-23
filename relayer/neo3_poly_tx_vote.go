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
	"github.com/devfans/zion-sdk/contracts/native/go_abi/info_sync_abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/polynetwork/bridge-common/chains/bridge"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/neo3"
	"sync"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer/zion"
	"github.com/polynetwork/poly-relayer/store"
)

type Neo3PolyTxVoteHandler struct {
	context.Context
	wg                  *sync.WaitGroup
	height              uint64
	zionReplenishHeight uint64
	listener            IChainListener
	submitter           *neo3.Submitter
	config              *config.Neo3PolyTxVoteConfig
	store               *store.Store
	bridge              *bridge.SDK
}

func NewNeo3PolyTxVoteHandler(config *config.Neo3PolyTxVoteConfig) *Neo3PolyTxVoteHandler {
	return &Neo3PolyTxVoteHandler{
		listener:  new(zion.Listener),
		submitter: new(neo3.Submitter),
		config:    config,
	}
}

func (h *Neo3PolyTxVoteHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg

	if h.config.CheckFee {
		h.bridge, err = bridge.WithOptions(0, config.CONFIG.Bridge, time.Minute, 10)
		if err != nil {
			return
		}
	}

	err = h.submitter.Init(h.config.SubmitterConfig)
	if err != nil {
		return
	}

	err = h.listener.Init(h.config.Poly, nil)
	if err != nil {
		return
	}
	h.store, err = store.NewStore(h.Chain())
	return
}

func (h *Neo3PolyTxVoteHandler) startReplenish() {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := base.BlocksToWait(h.listener.ChainId())
	var (
		latest uint64
		ok     bool
	)
	for {
		select {
		case <-h.Done():
			log.Info("Neo3 poly tx vote replenish scan is exiting now", "chain", h.config.ChainId)
			return
		default:
		}

		h.zionReplenishHeight++
		if latest < h.zionReplenishHeight+confirms {
			latest, ok = h.listener.WaitTillHeight(h.Context, h.zionReplenishHeight+confirms, time.Duration(1)*time.Second)
		}
		if !ok {
			log.Info("Neo3 poly tx vote replenish scan is exiting now", "chain", h.config.ChainId)
			break
		}

		log.Info("Scanning Neo3 poly tx vote replenish in block", "poly height", h.zionReplenishHeight)
		opt := &bind.FilterOpts{
			Start:   h.zionReplenishHeight,
			End:     &h.zionReplenishHeight,
			Context: context.Background(),
		}

		var err error
		var events *info_sync_abi.IInfoSyncReplenishEventIterator
		if zl, ok := h.listener.(*zion.Listener); ok {
			// Since neo3(as src chain) doesn't need header sync, so InfoSync is reused to replenish neo3 poly tx vote
			events, err = zl.SDK().Node().IInfoSync.FilterReplenishEvent(opt)
		} else {
			log.Fatal("listener of Neo3PolyTxVoteHandler is not zion.Listener")
		}

		if err != nil {
			log.Error("Fetch header sync replenish events error", "chain", h.config.ChainId, "zion height", h.zionReplenishHeight, "err", err)
			h.zionReplenishHeight--
			continue
		}

		for events.Next() {
			ev := events.Event
			if h.Chain() != ev.ChainID {
				continue
			}

			for _, height := range ev.Heights {
				var list []*store.Tx
				log.Info("Neo3 poly tx vote replenish processing block", "height", height, "chain", h.config.ChainId)
				txs, err := h.listener.(*zion.Listener).ScanNeo3Tx(uint64(height))
				if err != nil {
					log.Error("Neo3 poly tx vote replenish fetch zion txs failure", "chain", h.config.ChainId, "poly height", height, "err", err)
					continue
				}
				for _, tx := range txs {
					log.Info("Neo3 poly tx vote replenish found poly tx", "from", tx.SrcChainId, "to", tx.DstChainId, "poly height", height, "poly hash", tx.PolyHash.Hex())
					list = append(list, store.NewTx(tx))
				}
				if h.store.InsertTxs(list) != nil {
					log.Error("Save neo3 poly tx failed", "poly height", h.height, "len(txs)", len(list), "err", err)
				}
			}
		}
	}
}

func (h *Neo3PolyTxVoteHandler) replenish() {
	zionHeight, err := h.listener.LatestHeight()
	if err != nil {
		log.Error("Failed to get zion latest height err ", "err", err)
		return
	}
	h.zionReplenishHeight = zionHeight
	log.Info("Neo3 poly tx vote replenish will start...", "chain", h.config.ChainId, "zion height", h.zionReplenishHeight)

	go h.startReplenish()
	return
}

func (h *Neo3PolyTxVoteHandler) start() (err error) {
	h.wg.Add(1)
	defer h.wg.Done()
	confirms := base.BlocksToWait(h.listener.ChainId())
	var (
		latest uint64
		ok     bool
	)
	for {
		select {
		case <-h.Done():
			log.Info("Neo3 poly tx vote handler is exiting...", "chain", h.config.ChainId, "poly height", h.height)
			return nil
		default:
		}

		var txs []*msg.Tx

		h.height++
		if latest < h.height+confirms {
			latest, ok = h.listener.Nodes().WaitTillHeight(h.Context, h.height+confirms, h.listener.ListenCheck())
			if !ok {
				continue
			}
		}
		log.Info("Scanning neo3 poly txs in block", "height", h.height, "chain", h.listener.ChainId())

		if listener, ok := h.listener.(*zion.Listener); ok {
			txs, err = listener.ScanNeo3Tx(h.height)
		} else {
			log.Fatal("listener of Neo3PolyTxVoteHandler is not zion.Listener")
		}

		if err == nil {
			var list []*store.Tx
			for _, tx := range txs {
				log.Info("Found poly tx", "from", tx.SrcChainId, "to", tx.DstChainId, "hash", tx.PolyHash.Hex())
				list = append(list, store.NewTx(tx))
			}
			err = h.store.InsertTxs(list)
			if err == nil {
				err = h.store.SetTxHeight(h.height)
				if err != nil {
					log.Error("Update neo3 poly tx vote height failure", "chain", h.config.ChainId, "height", h.height, "err", err)
				}
				continue
			} else {
				log.Error("Save neo3 poly tx failed", "poly height", h.height, "len(txs)", len(list), "err", err)
			}
		} else {
			log.Error("Fetch neo3 poly tx failed", "poly height", h.height, "err", err)
		}

		log.Error("Fetch zion txs failure", "chain", h.config.ChainId, "poly height", h.height, "err", err)
		h.height--
		time.Sleep(time.Second * 5)
	}
}

func (h *Neo3PolyTxVoteHandler) Start() (err error) {
	if h.config.PolyStartHeight != 0 {
		h.height = h.config.PolyStartHeight
	} else {
		h.height, err = h.store.GetTxHeight()
		if err != nil {
			log.Error("get neo3 poly tx vote start height from store failed", "err", err)
			return
		}
	}

	log.Info("Neo3 poly tx vote will start...", "height", h.height+1, "chain", h.config.ChainId)
	h.submitter.StartPolyTxVote(h.Context, h.wg, h.config, h.store, h.bridge)
	go h.start()
	go h.replenish()
	return
}

func (h *Neo3PolyTxVoteHandler) Stop() (err error) {
	return
}

func (h *Neo3PolyTxVoteHandler) Chain() uint64 {
	return h.config.ChainId
}
