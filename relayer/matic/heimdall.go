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
	"bytes"

	"github.com/polynetwork/bridge-common/chains/matic"
	"github.com/polynetwork/bridge-common/chains/matic/cosmos"
	"github.com/polynetwork/poly-relayer/relayer/eth"
)

type HeimdallListener struct {
	tc *matic.SDK
	*eth.Listener
}

func (l *Listener) HeimdallHeader(height uint64) (header []byte, err error) {
	h := int64(height)
	rc, err := l.tc.Node().Commit(&h)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(rc.Header.ValidatorsHash, rc.Header.NextValidatorsHash) {
		return nil, nil
	}
	vs, err := l.tc.Node().GetValidators(height)
	if err != nil {
		return
	}
	hdr := cosmos.CosmosHeader{
		Header:  *rc.Header,
		Commit:  rc.Commit,
		Valsets: vs,
	}
	header, err = l.tc.Node().MarshalHeader(hdr)
	return
}

func (l *HeimdallListener) GetEpochSwitch() (info *cosmos.CosmosEpochSwitchInfo, err error) {
	data, err := l.Poly().Node().GetSideChainEpoch(l.ChainId())
	if err != nil {
		return nil, err
	}
	info, err = matic.ParseEpochSwitch(data)
	return
}
