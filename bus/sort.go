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
	"strconv"

	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/poly-relayer/msg"
)

type SortedTxQueueKey TxQueueKey

func (k *SortedTxQueueKey) Key() string {
	return fmt.Sprintf("%s:relayer:sorted_bus:%v:%v", base.ENV, k.ChainId, k.TxType)
}

type SortedTxBus interface {
	Push(context.Context, *msg.Tx, uint64) error
	Pop(context.Context, uint64, int64) ([]*msg.Tx, error)
	Len(context.Context) (uint64, error)
	Topic() string
}

type RedisSortedTxBus struct {
	Key
	db *redis.Client
}

func NewRedisSortedTxBus(db *redis.Client, chainId uint64, txType msg.TxType) *RedisSortedTxBus {
	bus := &RedisSortedTxBus{
		db:  db,
		Key: &SortedTxQueueKey{ChainId: chainId, TxType: txType},
	}
	return bus
}

func (b *RedisSortedTxBus) Topic() (topic string) {
	return b.Key.Key()
}

func (b *RedisSortedTxBus) Len(ctx context.Context) (uint64, error) {
	v, err := b.db.ZCount(ctx, b.Key.Key(), "0", "+inf").Result()
	if err != nil {
		return 0, fmt.Errorf("Get chain sorted tx queue length error %v", err)
	}
	return uint64(v), nil
}

func (b *RedisSortedTxBus) Push(ctx context.Context, msg *msg.Tx, height uint64) (err error) {
	_, err = b.db.ZAdd(ctx, b.Key.Key(),
		&redis.Z{
			Score:  float64(height),
			Member: msg.Encode(),
		},
	).Result()
	return
}

func (b *RedisSortedTxBus) Pop(ctx context.Context, height uint64, count int64) (txs []*msg.Tx, err error) {
	max := strconv.Itoa(int(height))
	res, err := b.db.ZRangeByScore(ctx, b.Key.Key(),
		&redis.ZRangeBy{Max: max, Count: count},
	).Result()
	if err != nil {
		return
	}
	if len(res) == 0 {
		return
	}
	txs = make([]*msg.Tx, len(res))
	for i, item := range res {
		tx := new(msg.Tx)
		e := tx.Decode(item)
		if e != nil {
			err = e
		}
		txs[i] = tx
	}
	return
}
