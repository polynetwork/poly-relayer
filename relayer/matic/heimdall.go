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
	"fmt"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/matic"
	"github.com/polynetwork/bridge-common/chains/matic/cosmos"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type HeimdallListener struct {
	sdk    *matic.SDK // heimdall tclient
	config *config.ListenerConfig
	poly   *poly.SDK
	name   string
}

func (l *HeimdallListener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
	l.config = config
	l.name = base.GetChainName(base.HEIMDALL)
	l.poly = poly
	l.sdk, err = matic.WithOptions(base.HEIMDALL, config.ExtraNodes, time.Minute, 1)
	return
}

func (l *HeimdallListener) Header(height uint64) (header []byte, hash []byte, err error) {
	h := int64(height)
	rc, err := l.sdk.Node().Commit(&h)
	if err != nil {
		return
	}
	if bytes.Equal(rc.Header.ValidatorsHash, rc.Header.NextValidatorsHash) {
		return nil, nil, nil
	}
	vs, err := l.sdk.Node().GetValidators(height)
	if err != nil {
		return
	}
	hdr := cosmos.CosmosHeader{
		Header:  *rc.Header,
		Commit:  rc.Commit,
		Valsets: vs,
	}
	header, err = l.sdk.Node().MarshalHeader(hdr)
	return
}

func (l *HeimdallListener) GetEpochSwitch() (info *cosmos.CosmosEpochSwitchInfo, err error) {
	data, err := l.poly.Node().GetSideChainEpoch(base.HEIMDALL)
	if err != nil {
		return nil, err
	}
	info, err = matic.ParseEpochSwitch(data)
	return
}

func (l *HeimdallListener) ChainId() uint64 {
	return base.HEIMDALL
}

func (l *HeimdallListener) Compose(tx *msg.Tx) error {
	return nil
}

func (l *HeimdallListener) Defer() int {
	return l.config.Defer
}

func (l *HeimdallListener) LastHeaderSync(force, last uint64) (uint64, error) {
	if l.poly == nil {
		return 0, fmt.Errorf("No poly sdk provided for listener", "chain", l.name)
	}

	if force != 0 {
		return force, nil
	}
	epoch, err := l.GetEpochSwitch()
	if err != nil {
		return 0, err
	}
	height := uint64(epoch.Height)
	if last > height {
		height = last
	}
	return height, nil
}

func (l *HeimdallListener) ListenCheck() time.Duration {
	duration := time.Second
	if l.config.ListenCheck > 0 {
		duration = time.Duration(l.config.ListenCheck) * time.Second
	}
	return duration
}

func (l *HeimdallListener) Nodes() chains.Nodes {
	return l.sdk.ChainSDK
}

func (l *HeimdallListener) GetTxBlock(hash string) (height uint64, err error) {
	return
}

func (l *HeimdallListener) ScanTx(hash string) (tx *msg.Tx, err error) {
	return
}

func (l *HeimdallListener) Scan(height uint64) (txs []*msg.Tx, err error) {
	return
}
