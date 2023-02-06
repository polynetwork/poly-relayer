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
	"github.com/polynetwork/poly-relayer/relayer/ripple"
	"sync"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/bridge"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/zion"
)

type PolyTxCommitHandler struct {
	context.Context
	wg *sync.WaitGroup

	bus       bus.TxBus
	queue     bus.DelayedTxBus // Delayed tx bus
	sequence  bus.Sequence     // Chain now sequence and sequenceTx
	submitter IChainSubmitter
	composer  *zion.Submitter
	config    *config.PolyTxCommitConfig

	bridge *bridge.SDK
}

func NewPolyTxCommitHandler(config *config.PolyTxCommitConfig) *PolyTxCommitHandler {
	return &PolyTxCommitHandler{
		config:    config,
		submitter: GetSubmitter(config.ChainId),
		composer:  new(zion.Submitter),
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
	if h.config.ChainId == base.RIPPLE {
		h.sequence = bus.NewRedisChainSequence(bus.New(h.config.Bus.Redis))
	}

	return
}

func (h *PolyTxCommitHandler) Compose(tx *msg.Tx) (err error) {
	err = h.composer.ComposeTx(tx)
	if err != nil {
		return
	}
	if h.config.Filter != nil {
		if !h.config.Filter.Check(tx) {
			log.Warn("Poly tx commit skipped for not target", "from", tx.SrcProxy, "to", tx.DstProxy)
			return msg.ERR_TX_BYPASS
		} else {
			log.Info("Poly tx commit proxy filter passed", "from", tx.SrcProxy, "to", tx.DstProxy)
		}
	}
	return
}

func (h *PolyTxCommitHandler) Start() (err error) {
	mq := h.bus
	if h.config.Filter != nil {
		mq = bus.WithTxFilter(h.bus, h.config.Filter)
	}
	{
		bus := &CommitFilter{
			name:     base.GetChainName(h.config.ChainId),
			TxBus:    mq,
			checkFee: h.config.CheckFee,
			delay:    h.queue,
			ch:       make(chan *msg.Tx, 100),
			bridge:   h.bridge,
		}
		go bus.Pipe(h.Context, h.wg)
		mq = bus
	}
	if h.config.ChainId == base.RIPPLE {
		if rippleSubmitter, ok := h.submitter.(*ripple.Submitter); ok {
			err = rippleSubmitter.StartRipple(h.Context, h.wg, mq, h.queue, h.Compose, h.sequence)
		} else {
			err = fmt.Errorf("start ripple submitter error, type assertion failed")
		}
	} else {
		err = h.submitter.Start(h.Context, h.wg, mq, h.queue, h.Compose)
	}

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
	checkFee bool
	delay    bus.DelayedTxBus
	ch       chan *msg.Tx
	bridge   *bridge.SDK
}

func (b *CommitFilter) Pop(ctx context.Context) (tx *msg.Tx, err error) {
	select {
	case <-ctx.Done():
		err = fmt.Errorf("Exit signal received")
	case tx = <-b.ch:
		log.Info("Check fee passed tx", "poly_hash", tx.PolyHash.Hex())
	}
	return
}

func (b *CommitFilter) flush(ctx context.Context, txs []*msg.Tx) (err error) {
	// Check fee here:
	// Pass -> send to submitter
	// EstimatePay -> send to submitter
	// NotPass -> send to delay queue
	// Missing -> send to delay queue
	state := map[string]*bridge.CheckFeeRequest{}
	for _, tx := range txs {
		state[tx.PolyHash.Hex()] = &bridge.CheckFeeRequest{
			ChainId:  tx.SrcChainId,
			TxId:     tx.TxId,
			PolyHash: tx.PolyHash.Hex(),
		}
	}
	log.Info("Sending check fee request", "size", len(state), "chain", b.name)
	err = b.bridge.Node().CheckFee(state)
	if err != nil {
		return
	}
	for _, tx := range txs {
		feeMin := float32(0)
		feePaid := float32(0)
		check := state[tx.PolyHash.Hex()]
		if check != nil {
			tx.CheckFeeStatus = state[tx.PolyHash.Hex()].Status
			feeMin = float32(check.Min)
			feePaid = float32(check.Paid)
			tx.PaidGas = float64(check.PaidGas)
		}

		if check.Pass() {
			b.ch <- tx
			log.Info("CheckFee pass", "poly_hash", tx.PolyHash, "min", feeMin, "paid", feePaid)
		} else if check.PaidLimit() {
			b.ch <- tx
			log.Info("CheckFee EstimatePay", "poly_hash", tx.PolyHash, "paidGas", tx.PaidGas, "min", feeMin, "paid", feePaid)
		} else if check.Skip() {
			log.Warn("Skipping poly for marked as not target in fee check", "poly_hash", tx.PolyHash)
		} else if check.Missing() {
			tx.Attempts++
			log.Info("CheckFee tx missing in bridge, delay for 2 seconds", "poly_hash", tx.PolyHash)
			tsp := time.Now().Unix() + 5
			bus.SafeCall(ctx, tx, "push to delay queue", func() error { return b.delay.Delay(context.Background(), tx, tsp) })

		} else {
			tx.Attempts++
			log.Info("CheckFee tx not paid, delay for 10 minutes", "poly_hash", tx.PolyHash, "min", feeMin, "paid", feePaid)
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
			tx, _ := b.TxBus.PopTimed(ctx, time.Second)
			if tx != nil {
				if tx.Type() == msg.POLY_EPOCH {
					log.Info("Found new poly epoch info", "poly_epoch", tx.PolyEpoch.EpochId, "chain", b.name)
					b.ch <- tx
					continue
				}

				if msg.Empty(tx.PolyHash) {
					log.Error("Invalid poly tx, poly hash missing", "body", tx.Encode())
					continue
				}
				if tx.Attempts > 1000 && base.ENV == "testnet" {
					log.Error("Dropping failed tx for too many retries in testnet", "chain", b.name, "poly_hash", tx.PolyHash)
					continue
				}
				log.Info("Check fee pending", "chain", b.name, "poly_hash", tx.PolyHash.Hex(), "process_pending", len(b.ch))

				// Skip tx check fee
				if !b.checkFee {
					tx.CheckFeeOff = true
					b.ch <- tx
				} else if tx.SkipFee() {
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
	for _, tx := range txs {
		bus.SafeCall(ctx, tx, "push back to tx bus", func() error { return b.TxBus.Push(context.Background(), tx) })
	}
	log.Info("Check fee queu exiting now...", "chain", b.name)
}

type SrcTxCommitHandler struct {
	context.Context
	wg *sync.WaitGroup

	bus       bus.SortedTxBus
	submitter *zion.Submitter
	listener  IChainListener
	config    *config.SrcTxCommitConfig
}

func NewSrcTxCommitHandler(config *config.SrcTxCommitConfig) *SrcTxCommitHandler {
	return &SrcTxCommitHandler{
		config:    config,
		submitter: new(zion.Submitter),
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

	h.bus = bus.NewRedisSortedTxBus(bus.New(h.config.Bus.Redis), h.config.ChainId, msg.SRC)
	err = h.listener.Init(h.config.ListenerConfig, h.submitter.Poly())
	return
}

func (h *SrcTxCommitHandler) Start() (err error) {
	mq := h.bus
	if h.config.Filter != nil {
		mq = bus.WithFilter(h.bus, h.config.Filter)
	}
	err = h.submitter.Run(h.Context, h.wg, mq, h.listener)
	return
}

func (h *SrcTxCommitHandler) Stop() (err error) {
	return
}

func (h *SrcTxCommitHandler) Chain() uint64 {
	return h.config.ChainId
}
