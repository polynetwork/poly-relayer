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

package plt

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
)

type Listener struct {
	*eth.Listener
	vs []common.Address
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	hdr, err := l.SDK().Node().HeaderByNumber(context.Background(), big.NewInt(int64(height)))
	if err != nil {
		err = fmt.Errorf("Fetch block header error %v", err)
		return nil, nil, err
	}
	log.Info("Fetched block header", "chain", l.Name(), "height", height, "hash", hdr.Hash().String())
	extra, err := types.ExtractIstanbulExtra(hdr)
	if err != nil {
		return
	}
	if isEpoch(extra.Validators, l.vs) {
		l.vs = extra.Validators
	} else {
		return
	}
	header, err = hdr.MarshalJSON()
	return
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	err = l.Listener.Compose(tx)
	if err != nil {
		return
	}
	block, err := l.SDK().Node().BlockByNumber(context.Background(), big.NewInt(int64(tx.SrcProofHeight)))
	if err != nil {
		return
	}
	tx.SrcStateRoot, err = block.Header().MarshalJSON()
	return
}

func (l *Listener) LastHeaderSync(force, last uint64) (height uint64, err error) {
	if l.Poly() == nil {
		err = fmt.Errorf("No poly sdk provided for listener", "chain", l.Name())
		return
	}

	height, err = l.Poly().Node().GetSideChainConsensusBlockHeight(base.PLT)
	if err != nil {
		return
	}
	data, err := l.Poly().Node().GetSideChainConsensusPeer(base.PLT)
	if err != nil {
		return
	}

	l.vs, err = bytes2Valset(data)
	if err != nil {
		return
	}

	if last > height {
		height = last
	}

	if force != 0 {
		return force, nil
	}

	return
}
