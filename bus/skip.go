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
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/msg"
)

type SkipCheck interface {
	Skip(context.Context, *msg.Tx) error
	CheckSkip(context.Context, *msg.Tx) (bool, error)
}

type RedisSkipCheck struct {
	Key
	db *redis.Client
}

func NewRedisSkipCheck(db *redis.Client) *RedisSkipCheck {
	return &RedisSkipCheck{String("skip_map"), db}
}

func formatHashes(strs ...string) []string {
	hashes := []string{}
	for _, hash := range strs {
		hash = strings.ToLower(strings.TrimSpace(hash))
		if hash != "" {
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

func (b *RedisSkipCheck) Skip(ctx context.Context, tx *msg.Tx) (err error) {
	hashes := formatHashes(tx.SrcHash, tx.PolyHash.String())
	for _, hash := range hashes {
		_, err = b.db.HSet(ctx, b.Key.Key(), hash, "true").Result()
		if err != nil {
			log.Error("Failed to skip tx", "err", err, "hash", hash)
		} else {
			log.Info("Tx marked to skip", "hash", hash)
		}
	}
	return
}

func (b *RedisSkipCheck) CheckSkip(ctx context.Context, tx *msg.Tx) (skip bool, err error) {
	hashes := formatHashes(tx.SrcHash, tx.PolyHash.String())
	var res string
	for _, hash := range hashes {
		res, err = b.db.HGet(ctx, b.Key.Key(), hash).Result()
		if res == "true" {
			return true, nil
		}
	}
	return
}
