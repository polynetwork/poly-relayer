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

	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/msg"
)

func SafeCall(ctx context.Context, tx *msg.Tx, msg string, f func() error) error {
	return Retry(ctx, func() error {
		err := f()
		if err != nil {
			log.Error(fmt.Sprintf("Failed call: %s", msg), "err", err, "body", tx.Encode())
		}
		return err
	}, time.Second, 0)

}

func Retry(ctx context.Context, f func() error, interval time.Duration, count int) error {
	c := 0
	var err error
	for {
		if count > 0 {
			if c > count {
				return err
			} else {
				c++
			}
		}
		err = f()
		if err == nil {
			return nil
		}
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return err
		}
	}
}
