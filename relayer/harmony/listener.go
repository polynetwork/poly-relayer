/*
 * Copyright (C) 2022 The poly network Authors
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

package harmony

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/harmony"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/polynetwork/poly/native/service/governance/side_chain_manager"
)

type Listener struct {
	*eth.Listener
	sdk *harmony.SDK
	poly *poly.SDK
	epoch uint64
	header []byte // Pending header
	blocksPerEpoch uint64
	nextEpochBlock uint64
}

func (l *Listener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
	l.Listener = new(eth.Listener)
	l.poly = poly
	err = l.Listener.Init(config, poly)
	if err != nil { return }
	l.sdk, err = harmony.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	if base.ENV == "mainnet" { l.blocksPerEpoch =  32768 } else { l.blocksPerEpoch = 8192 }
	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	if l.nextEpochBlock > 0 && height < l.nextEpochBlock &&
		height > l.nextEpochBlock - l.blocksPerEpoch + 1 { return }
	hdr, err := l.sdk.Node().HeaderByNumber(height)
	if err != nil {
		err = fmt.Errorf("Fetch block header error %v", err)
		return nil, nil, err
	}
	log.Info("Fetched block header", "chain", l.Name(), "height", height, )
	if l.header != nil {
		sig, err := hdr.GetLastCommitSignature()
		if err != nil { return nil, nil, err }
		bitmap, err := hdr.GetLastCommitBitmap()
		if err != nil { return nil, nil, err }
		hs := harmony.HeaderWithSig{l.header, sig, bitmap}
		header, err = hs.Encode()
		if err != nil {
			return nil, nil, err
		}
		l.header = nil
		return header, nil, nil
	}

	epoch := hdr.Epoch.Uint64()
	if epoch <= l.epoch {
		return
	}

	l.header, err = l.sdk.Node().HeaderByNumberRLP(height)
	if err == nil {
		l.epoch = epoch
		l.nextEpochBlock = height + l.blocksPerEpoch - 1
	}
	return
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	err = l.Listener.Compose(tx)
	if err != nil { return }
	header, err := l.sdk.Node().HeaderByNumberRLP(tx.SrcProofHeight)
	if err != nil {
		return
	}
	nextHeader, err := l.sdk.Node().HeaderByNumber(tx.SrcProofHeight + 1)
	if err != nil { return }
	sig, err := nextHeader.GetLastCommitSignature()
	if err != nil { return  }
	bitmap, err := nextHeader.GetLastCommitBitmap()
	if err != nil { return }
	hs := harmony.HeaderWithSig{header, sig, bitmap}
	tx.SrcStateRoot, err = hs.Encode()
	return
}

func (l *Listener) GenesisHeader(height uint64) (data []byte, err error) {
	header, err := l.sdk.Node().HeaderByNumberRLP(height)
	if err != nil {
		return
	}
	nextHeader, err := l.sdk.Node().HeaderByNumber(height + 1)
	if err != nil { return }
	sig, err := nextHeader.GetLastCommitSignature()
	if err != nil { return  }
	bitmap, err := nextHeader.GetLastCommitBitmap()
	if err != nil { return }
	hs := harmony.HeaderWithSig{header, sig, bitmap}
	data, err = hs.Encode()
	return
}

type Context struct {
	NetworkID int
}

func (l *Listener) SideChain() (sc *side_chain_manager.SideChain, err error) {
	sc = &side_chain_manager.SideChain{
		ChainId: base.HARMONY,
		Name: "harmony",
		BlocksToWait: 1,
	}
	ctx := &Context{}
	if config.CONFIG.Env == "mainnet" {
		ctx.NetworkID = 1
	}
	sc.ExtraInfo, err = json.Marshal(ctx)
	return
}

