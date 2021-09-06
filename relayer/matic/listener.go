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

package matic

import (
	"context"
	"fmt"
	"math/big"

	"github.com/polynetwork/bridge-common/chains/matic"
	"github.com/polynetwork/poly-relayer/relayer/eth"
)

type Listener struct {
	*eth.Listener
}

func (l *Listener) Header(height uint64) (header []byte, err error) {
	hdr, err := l.sdk.Node().HeaderByNumber(context.Background(), big.NewInt(int64(height)))
	if err != nil {
		err = fmt.Errorf("Fetch block header error %v", err)
		return nil, err
	}
	header := &matic.HeaderWithOptionalProof{
		Header: *hdr,
	}
	if (hdr.Number().Uint64()+1)%matic.SPRINT_SIZE == 0 {
		ch, err := l.GetBaseCosmosHeight()
		if err != nil {
			return nil, err
		}
		spanId, err := l.GetSpanId(height)
		if err != nil {
			return nil, err
		}
		if spanId == 0 {
			return nil, fmt.Errorf("Span ID missing for block %d", height)
		}
		latestSpan, err := l
	}

	return hdr.MarshalJSON()
}

func (l *Listener) GetSpanId(height uint64) (id uint64, err error) {
	return
}

func (l *Listener) GetBestCosmosHeight() (height uint64, err error) {
	return
}
