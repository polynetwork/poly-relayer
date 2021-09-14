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
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/matic"
	"github.com/polynetwork/bridge-common/chains/matic/cosmos"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/polynetwork/poly/common"
)

type Listener struct {
	spans map[uint64][2]uint64 // spanId -> [start, end]
	span  [3]uint64            // latest span: [spanId, start, end]
	sync.RWMutex

	tc           *matic.SDK
	lastSpanSync uint64
	*eth.Listener
}

func (l *Listener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
	l.Listener = new(eth.Listener)
	err = l.Listener.Init(config, poly)
	if err != nil {
		return
	}
	l.spans = map[uint64][2]uint64{}
	l.tc, err = matic.WithOptions(base.HEIMDALL, config.ExtraNodes, time.Minute, 1)
	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	hdr, err := l.SDK().Node().HeaderByNumber(context.Background(), big.NewInt(int64(height)))
	if err != nil {
		err = fmt.Errorf("Fetch block header error %v", err)
		return
	}
	hp := &cosmos.HeaderWithOptionalProof{
		Header: *hdr,
	}
	if (hdr.Number.Uint64()+1)%matic.SPRINT_SIZE == 0 {
		spanId, err := l.GetBorSpanId(height)
		if err != nil {
			return nil, nil, err
		}

		if spanId > l.lastSpanSync {
			hmHeight, err := l.GetBestCosmosHeight()
			if err != nil {
				return nil, nil, err
			}
			if spanId == 0 {
				return nil, nil, fmt.Errorf("Span ID missing for block %d", height)
			}
			err = l.tc.Node().ComposeHeaderProof(height, hmHeight, spanId, hp)
			if err != nil {
				return nil, nil, err
			}
			l.lastSpanSync = spanId
		}
	}
	header, err = json.Marshal(hp)
	return
}

func (l *Listener) GetSpanRange(id uint64) (start uint64, end uint64, err error) {
	l.RLock()
	if r, ok := l.spans[id]; ok {
		start = r[0]
		end = r[1]
	}
	l.RUnlock()
	if end != 0 {
		return
	}
	span, err := l.tc.Node().GetSpan(id)
	if err != nil {
		return
	}
	l.Lock()
	l.spans[id] = [2]uint64{span.StartBlock, span.EndBlock}
	l.Unlock()
	return span.StartBlock, span.EndBlock, nil
}

func (l *Listener) GetLatestSpan() (spandId uint64, start uint64, end uint64) {
	l.RLock()
	defer l.RUnlock()
	return l.span[0], l.span[1], l.span[2]
}

func (l *Listener) FetchLatestSpan() (spandId uint64, start uint64, end uint64, err error) {
	span, err := l.tc.Node().GetLatestSpan(0)
	if err != nil {
		return
	}
	l.Lock()
	l.span = [3]uint64{span.ID, span.StartBlock, span.EndBlock}
	l.spans[span.ID] = [2]uint64{span.StartBlock, span.EndBlock}
	l.Unlock()
	return span.ID, span.StartBlock, span.EndBlock, nil
}

func (l *Listener) GetBorSpanId(height uint64) (id uint64, err error) {
	span, start, end := l.GetLatestSpan()
	for {
		if height >= start && height <= end {
			return span, nil
		} else if height < start {
			// old span
			span--
			start, end, err = l.GetSpanRange(span)
			if err != nil {
				return
			}
		} else {
			// new span
			span, start, end, err = l.FetchLatestSpan()
			if err != nil {
				return
			}
		}
	}
	return
}

func (l *Listener) GetBestCosmosHeight() (height uint64, err error) {
	data, err := l.Poly().Node().GetSideChainEpoch(l.ChainId())
	if err != nil {
		return
	}
	info := new(cosmos.CosmosEpochSwitchInfo)
	err = info.Deserialization(common.NewZeroCopySource(data))
	if err != nil {
		return
	}
	height = uint64(info.Height)
	return
}
