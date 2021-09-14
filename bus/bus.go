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

	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/msg"
)

type Key interface {
	Key() string
}

type String string

func (s String) Key() string {
	return fmt.Sprintf("%s:%s", base.ENV, string(s))
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
	Push(context.Context, *msg.Tx) error
	PushToChain(context.Context, *msg.Tx) error
	PushBack(context.Context, *msg.Tx) error
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

func (b *RedisTxBus) Topic() (topic string) {
	return b.Key.Key()
}

func (b *RedisTxBus) Pop(ctx context.Context) (*msg.Tx, error) {
	c, _ := context.WithCancel(ctx)
	res, err := b.db.BLPop(c, 0, b.Key.Key()).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to pop message %v", err)
	}
	if len(res) < 2 || res[1] == "" || res[1] == "nil" {
		log.Info("Empty queue", "key", b.Key.Key())
		return nil, nil
	}
	tx := new(msg.Tx)
	err = tx.Decode(res[1])
	return tx, err
}

func (b *RedisTxBus) PushToChain(ctx context.Context, tx *msg.Tx) error {
	_, err := b.db.RPush(ctx, GetQueue(tx).Key(), tx.Encode()).Result()
	if err != nil {
		return fmt.Errorf("Failed to push message %v", err)
	}
	return nil
}

func (b *RedisTxBus) Push(ctx context.Context, tx *msg.Tx) error {
	_, err := b.db.RPush(ctx, b.Key.Key(), tx.Encode()).Result()
	if err != nil {
		return fmt.Errorf("Failed to push message %v", err)
	}
	return nil
}

func (b *RedisTxBus) PushBack(ctx context.Context, tx *msg.Tx) error {
	_, err := b.db.LPush(ctx, GetQueue(tx).Key(), tx.Encode()).Result()
	if err != nil {
		return fmt.Errorf("Failed to push message %v", err)
	}
	return nil
}
