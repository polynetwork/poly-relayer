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

package bus

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Key interface {
	Key() string
}

type String string

func (s String) Key() string {
	return fmt.Sprintf("%s:relayer:%s", base.ENV, string(s))
}

func NewPatchKey(chainId uint64) String {
	return String(fmt.Sprintf("patch:%d", chainId))
}

type TxQueueKey struct {
	ChainId uint64
	TxType  msg.TxType
}

func (k *TxQueueKey) Key() string {
	return fmt.Sprintf("%s:relayer:bus:%v:%v", base.ENV, k.ChainId, k.TxType)
}

func GetQueue(tx *msg.Tx) *TxQueueKey {
	return &TxQueueKey{
		ChainId: tx.DstChainId,
		TxType:  tx.Type(),
	}
}

type Bus interface {
	Pop() (msg.Message, error)
	Push(msg.Message) error
	PushBack(msg.Message) error
}

type TxBus interface {
	Pop(context.Context) (*msg.Tx, error)
	PopTimed(context.Context, time.Duration) (*msg.Tx, error)
	Push(context.Context, *msg.Tx) error
	PushToChain(context.Context, *msg.Tx) error
	Patch(context.Context, *msg.Tx) error
	PushBack(context.Context, *msg.Tx) error
	Len(context.Context) (uint64, error)
	LenOf(context.Context, uint64, msg.TxType) (uint64, error)
	Topic() string
}

type RedisTxBus struct {
	Key
	db *redis.Client
}

func NewRedisTxBus(db *redis.Client, chainId uint64, txType msg.TxType) *RedisTxBus {
	bus := &RedisTxBus{
		db:  db,
		Key: &TxQueueKey{ChainId: chainId, TxType: txType},
	}
	return bus
}

func NewRedisPatchTxBus(db *redis.Client, chainId uint64) *RedisTxBus {
	return &RedisTxBus{NewPatchKey(chainId), db}
}

func (b *RedisTxBus) Topic() (topic string) {
	return b.Key.Key()
}

func (b *RedisTxBus) Pop(ctx context.Context) (*msg.Tx, error) {
	return b.PopTimed(ctx, 0)
}

func (b *RedisTxBus) PopTimed(ctx context.Context, duration time.Duration) (*msg.Tx, error) {
	res, err := b.db.BLPop(ctx, duration, b.Key.Key()).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to pop message %v", err)
	}
	if len(res) < 2 || res[1] == "" || res[1] == "nil" {
		log.Info("Empty queue", "key", b.Key.Key())
		return nil, nil
	}
	tx := new(msg.Tx)
	err = tx.Decode(res[1])
	log.Debug("Tx pop:", "msg", string(res[1]))
	return tx, err
}

func (b *RedisTxBus) PushToChain(ctx context.Context, tx *msg.Tx) error {
	log.Debug("Tx push to chain:", "msg", util.Json(tx))
	_, err := b.db.RPush(ctx, GetQueue(tx).Key(), tx.Encode()).Result()
	if err != nil {
		return fmt.Errorf("Failed to push message %v", err)
	}
	return nil
}

func (b *RedisTxBus) Patch(ctx context.Context, tx *msg.Tx) (err error) {
	chain := tx.SrcChainId
	if tx.Type() == msg.POLY {
		chain = base.POLY
	}
	_, err = b.db.RPush(ctx, NewPatchKey(chain).Key(), tx.Encode()).Result()
	if err != nil {
		return fmt.Errorf("Failed to push message %v", err)
	}
	return nil
}

func (b *RedisTxBus) Push(ctx context.Context, tx *msg.Tx) error {
	log.Debug("Tx push:", "msg", util.Json(tx))
	_, err := b.db.RPush(ctx, b.Key.Key(), tx.Encode()).Result()
	if err != nil {
		return fmt.Errorf("Failed to push message %v", err)
	}
	return nil
}

func (b *RedisTxBus) PushBack(ctx context.Context, tx *msg.Tx) error {
	log.Debug("Tx patch back:", "msg", util.Json(tx))
	_, err := b.db.LPush(ctx, GetQueue(tx).Key(), tx.Encode()).Result()
	if err != nil {
		return fmt.Errorf("Failed to push message %v", err)
	}
	return nil
}

func (b *RedisTxBus) Len(ctx context.Context) (uint64, error) {
	v, err := b.db.LLen(ctx, b.Key.Key()).Result()
	if err != nil {
		return 0, fmt.Errorf("Get chain tx queue length error %v", err)
	}
	return uint64(v), nil
}

func (b *RedisTxBus) LenOf(ctx context.Context, chain uint64, ty msg.TxType) (uint64, error) {
	key := &TxQueueKey{chain, ty}
	v, err := b.db.LLen(ctx, key.Key()).Result()
	if err != nil {
		return 0, fmt.Errorf("Get chain tx queue length error %v", err)
	}
	return uint64(v), nil
}

type TxBusWithFilter struct {
	SortedTxBus
	filter *config.FilterConfig
}

func WithFilter(bus SortedTxBus, filter *config.FilterConfig) *TxBusWithFilter {
	return &TxBusWithFilter{bus, filter}
}

func (b *TxBusWithFilter) Pop(ctx context.Context) (*msg.Tx, uint64, error) {
	for {
		tx, score, err := b.SortedTxBus.Pop(ctx)
		if err != nil {
			return nil, 0, err
		}
		if b.filter.Check(tx.SrcProxy, tx.DstProxy) {
			log.Debug("Filter passes tx", "chain", tx.DstChainId, "src_proxy", tx.SrcProxy, "dst_proxy", tx.DstProxy)
			return tx, score, nil
		} else {
			log.Warn("Filter ignores tx", "chain", tx.DstChainId, "src_proxy", tx.SrcProxy, "dst_proxy", tx.DstProxy)
		}
	}
}
