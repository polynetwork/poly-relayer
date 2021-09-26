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
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/poly-relayer/msg"
)

type DelayedTxBus interface {
	Delay(context.Context, *msg.Tx, int64) error
	Pop(context.Context) (*msg.Tx, int64, error)
	Len(context.Context) (uint64, error)
}

type RedisDelayedTxBus struct {
	Key
	db *redis.Client
}

func NewRedisDelayedTxBus(db *redis.Client) *RedisDelayedTxBus {
	bus := &RedisDelayedTxBus{
		db:  db,
		Key: String("delayed_tx"),
	}
	return bus
}

func (b *RedisDelayedTxBus) Topic() (topic string) {
	return b.Key.Key()
}

func (b *RedisDelayedTxBus) Len(ctx context.Context) (uint64, error) {
	v, err := b.db.ZCount(ctx, b.Key.Key(), "0", strconv.Itoa(int(time.Now().Unix()))).Result()
	if err != nil {
		return 0, fmt.Errorf("Get chain delayed tx queue length error %v", err)
	}
	return uint64(v), nil
}

func (b *RedisDelayedTxBus) Delay(ctx context.Context, msg *msg.Tx, delay int64) (err error) {
	_, err = b.db.ZAdd(ctx, b.Key.Key(),
		&redis.Z{
			Score:  float64(delay),
			Member: msg.Encode(),
		},
	).Result()
	return
}

func (b *RedisDelayedTxBus) Pop(ctx context.Context) (tx *msg.Tx, score int64, err error) {
	c, _ := context.WithCancel(ctx)
	res, err := b.db.BZPopMin(c, 0, b.Key.Key()).Result()
	if err != nil {
		return
	}
	if res == nil {
		return
	}
	score = int64(res.Score)
	tx = new(msg.Tx)
	err = tx.Decode(res.Member.(string))
	return
}
