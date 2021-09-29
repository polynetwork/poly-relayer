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
	"github.com/polynetwork/bridge-common/chains/bridge"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/poly"
)

type PolyTxCommitHandler struct {
	context.Context
	wg *sync.WaitGroup

	bus       bus.TxBus
	queue     bus.DelayedTxBus // Delayed tx bus
	submitter IChainSubmitter
	composer  *poly.Submitter
	config    *config.PolyTxCommitConfig

	bridge *bridge.SDK
}

func NewPolyTxCommitHandler(config *config.PolyTxCommitConfig) *PolyTxCommitHandler {
	return &PolyTxCommitHandler{
		config:    config,
		submitter: GetSubmitter(config.ChainId),
		composer:  new(poly.Submitter),
	}
}

func (h *PolyTxCommitHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg

	if h.config.CheckFee {
		h.bridge, err = bridge.WithOptions(0, config.CONFIG.Bridge, time.Minute, 10)
		if err != nil {
			return
		}
	}

	if h.submitter == nil {
		return fmt.Errorf("Unabled to create submitter for chain %s", base.GetChainName(h.config.ChainId))
	}

	err = h.submitter.Init(h.config.SubmitterConfig)
	if err != nil {
		return
	}

	err = h.composer.Init(h.config.Poly)
	if err != nil {
		return
	}

	h.bus = bus.NewRedisTxBus(bus.New(h.config.Bus.Redis), h.config.ChainId, msg.POLY)
	h.queue = bus.NewRedisDelayedTxBus(bus.New(h.config.Bus.Redis))
	return
}

func (h *PolyTxCommitHandler) Start() (err error) {
	mq := h.bus
	if h.config.Filter != nil {
		mq = bus.WithFilter(h.bus, h.config.Filter)
	}
	if h.config.CheckFee {
		mq = &CommitFilter{
			name:   base.GetChainName(h.config.ChainId),
			TxBus:  mq,
			delay:  h.queue,
			ch:     make(chan *msg.Tx, 100),
			bridge: h.bridge,
		}
	}
	err = h.submitter.Start(h.Context, h.wg, mq, h.queue, h.composer.ComposeTx)
	return
}

func (h *PolyTxCommitHandler) Stop() (err error) {
	return
}

func (h *PolyTxCommitHandler) Chain() uint64 {
	return h.config.ChainId
}

type CommitFilter struct {
	name string
	bus.TxBus
	delay  bus.DelayedTxBus
	ch     chan *msg.Tx
	bridge *bridge.SDK
}

func (b *CommitFilter) Pop(ctx context.Context) (tx *msg.Tx, err error) {
	select {
	case <-ctx.Done():
		err = fmt.Errorf("Exit signal received")
	case tx = <-b.ch:
	}
	return
}

func (b *CommitFilter) flush(ctx context.Context, txs []*msg.Tx) (err error) {
	// Check fee here:
	// Pass -> send to submitter
	// NotPass -> send to delay queue
	// Missing -> send to delay queue
	state := map[string]*bridge.CheckFeeRequest{}
	for _, tx := range txs {
		state[tx.PolyHash] = &bridge.CheckFeeRequest{
			ChainId:  tx.SrcChainId,
			TxId:     tx.TxId,
			PolyHash: tx.PolyHash,
		}
	}
	err = b.bridge.Node().CheckFee(state)
	if err != nil {
		return
	}
	for _, tx := range txs {
		if state[tx.PolyHash] != nil {
			tx.CheckFeeStatus = state[tx.PolyHash].Status
		}

		if state[tx.PolyHash].Pass() {
			b.ch <- tx
			log.Info("CheckFee pass", "poly_hash", tx.PolyHash)
		} else if state[tx.PolyHash].Skip() {
			log.Warn("Skipping poly for marked as not target in fee check", "poly_hash", tx.PolyHash)
		} else if state[tx.PolyHash].Missing() {
			log.Info("CheckFee tx missing in bridge, delay for 2 seconds", "poly_hash", tx.PolyHash)
			tsp := time.Now().Unix() + 2
			bus.SafeCall(ctx, tx, "push to delay queue", func() error { return b.delay.Delay(context.Background(), tx, tsp) })

		} else {
			log.Info("CheckFee tx not paid, delay for 10 minutes", "poly_hash", tx.PolyHash)
			tsp := time.Now().Unix() + 600
			bus.SafeCall(ctx, tx, "push to delay queue", func() error { return b.delay.Delay(context.Background(), tx, tsp) })
		}
	}
	return
}

func (b *CommitFilter) Pipe(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	txs := []*msg.Tx{}
	flush := false
LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		default:
		}

		// Max poll size: 100
		if !flush || len(txs) < 100 {
			c, _ := context.WithTimeout(ctx, time.Second)
			tx, _ := b.TxBus.Pop(c)
			if tx != nil {
				if tx.PolyHash == "" {
					log.Error("Invalid poly tx, poly hash missing", "body", tx.Encode())
					continue
				}

				// Skip tx check fee
				if tx.SkipCheckFee {
					log.Info("CheckFee skipped for tx", "poly_hash", tx.PolyHash)
					b.ch <- tx
				} else if tx.CheckFeeStatus == bridge.PAID {
					b.ch <- tx
				} else {
					txs = append(txs, tx)
					flush = len(txs) > 10
				}
			} else {
				flush = len(txs) > 0
			}
		}
		if flush {
			err := b.flush(ctx, txs)
			if err == nil {
				flush = false
				txs = []*msg.Tx{}
			} else {
				log.Error("Check fee error", "chain", b.name, "err", err)
			}
		}
	}
	// Drain the buf
	log.Info("Pushing back check fee queue to poly tx bus", "chain", b.name, "size", len(b.ch))
	close(b.ch)
	for tx := range b.ch {
		bus.SafeCall(ctx, tx, "push back to tx bus", func() error { return b.TxBus.Push(context.Background(), tx) })
	}
	log.Info("Check fee queu exiting now...", "chain", b.name)
}

type SrcTxCommitHandler struct {
	context.Context
	wg *sync.WaitGroup

	bus       bus.TxBus
	submitter *poly.Submitter
	listener  IChainListener
	config    *config.SrcTxCommitConfig
}

func NewSrcTxCommitHandler(config *config.SrcTxCommitConfig) *SrcTxCommitHandler {
	return &SrcTxCommitHandler{
		config:    config,
		submitter: new(poly.Submitter),
		listener:  GetListener(config.ChainId),
	}
}

func (h *SrcTxCommitHandler) Init(ctx context.Context, wg *sync.WaitGroup) (err error) {
	h.Context = ctx
	h.wg = wg

	h.config.Poly.ChainId = h.config.ChainId
	err = h.submitter.Init(h.config.Poly)
	if err != nil {
		return
	}

	if h.listener == nil {
		return fmt.Errorf("Unabled to create listener for chain %s", base.GetChainName(h.config.ChainId))
	}

	h.bus = bus.NewRedisTxBus(bus.New(h.config.Bus.Redis), h.config.ChainId, msg.SRC)
	err = h.listener.Init(h.config.ListenerConfig, h.submitter.Poly())
	return
}

func (h *SrcTxCommitHandler) Start() (err error) {
	mq := h.bus
	if h.config.Filter != nil {
		mq = bus.WithFilter(h.bus, h.config.Filter)
	}
	err = h.submitter.Start(h.Context, h.wg, mq, h.listener.Compose)
	return
}

func (h *SrcTxCommitHandler) Stop() (err error) {
	return
}

func (h *SrcTxCommitHandler) Chain() uint64 {
	return h.config.ChainId
}
