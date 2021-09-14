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

package ok

import (
	"bytes"
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"

	"github.com/polynetwork/bridge-common/chains/ok"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/native/service/header_sync/cosmos"
)

type Listener struct {
	*eth.Listener
	tm    *ok.SDK
	codec *codec.Codec
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	cr, err := l.tm.Node().Tendermint().QueryCommitResult(int64(height))
	if err != nil {
		err = fmt.Errorf("OKex query commit result height %d error %v", height, err)
		return
	}
	if !bytes.Equal(cr.Header.ValidatorsHash, cr.Header.NextValidatorsHash) {
		vs, err := l.tm.Node().GetValidators(height)
		if err != nil {
			err = fmt.Errorf("OKex get validators height %d error %v", height, err)
			return nil, nil, err
		}
		hdr := cosmos.CosmosHeader{
			Header:  *cr.Header,
			Commit:  cr.Commit,
			Valsets: vs,
		}
		header, err = l.codec.MarshalBinaryBare(hdr)
		if err != nil {
			err = fmt.Errorf("OKex header marshal binary height %d, err %v", height, err)
		}
		return header, nil, err
	}
	return
}

func (l *Listener) LastHeaderSync(force uint64) (height uint64, err error) {
	if l.Poly() == nil {
		err = fmt.Errorf("No poly sdk provided for listener", "chain", l.ChainId())
		return
	}

	if force != 0 {
		return force, nil
	}
	epoch, err := l.Poly().Node().GetSideChainEpoch(l.ChainId())
	if err != nil {
		return
	}

	info := &cosmos.CosmosEpochSwitchInfo{}
	err = info.Deserialization(common.NewZeroCopySource(epoch))
	if err != nil {
		return
	}
	height = uint64(info.Height)
	return
}
