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
	"time"

	"github.com/polynetwork/bridge-common/chains/harmony"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
)

type Listener struct {
	*eth.Listener
	sdk            *harmony.SDK
	poly           *zion.SDK
	epoch          uint64
	header         []byte // Pending header
	nextEpochBlock uint64
}

const (
	EPOCH_START_MAINNET uint64 = 23592960
	EPOCH_START_TESTNET uint64 = 22172656

	EPOCH_BLOCKS_MAINNET uint64 = 32768
	EPOCH_BLOCKS_TESTNET uint64 = 8192
)

func GetLastEpochBlock(height uint64) (prev, next uint64) {
	start, blocks := EPOCH_START_TESTNET, EPOCH_BLOCKS_TESTNET
	if config.CONFIG.Env == "mainnet" {
		start, blocks = EPOCH_START_MAINNET, EPOCH_BLOCKS_MAINNET
	}
	step := (height - start) % blocks
	prev = height - step - 1
	next = prev + blocks
	return
}

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	l.Listener = new(eth.Listener)
	l.poly = poly
	err = l.Listener.Init(config, poly)
	if err != nil {
		return
	}
	l.sdk, err = harmony.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	prev, next := GetLastEpochBlock(height)
	if prev == height || next == height {
		header, err = l.genesisHeader(height)
		if err == nil {
			log.Info("Fetched block header", "chain", l.Name(), "height", height)
		}
	} else {
		log.Warn("Skipping harmony header fetch, for not last epoch",
			"height", height, "prev", prev, "next", next)
	}

	return
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	err = l.Listener.Compose(tx)
	if err != nil {
		return
	}
	header, err := l.sdk.Node().HeaderByNumberRLP(tx.SrcProofHeight)
	if err != nil {
		return
	}
	nextHeader, err := l.sdk.Node().HeaderByNumber(tx.SrcProofHeight + 1)
	if err != nil {
		return
	}
	sig, err := nextHeader.GetLastCommitSignature()
	if err != nil {
		return
	}
	bitmap, err := nextHeader.GetLastCommitBitmap()
	if err != nil {
		return
	}
	hs := harmony.HeaderWithSig{header, sig, bitmap}
	tx.SrcStateRoot, err = hs.Encode()
	return
}

func (l *Listener) GenesisHeader(height uint64) (data []byte, err error) {
	if height == 0 {
		height, err = l.sdk.Node().GetLatestHeight()
		if err != nil {
			return
		}
		height, _ = GetLastEpochBlock(height)
	}
	return l.genesisHeader(height)
}

func (l *Listener) genesisHeader(height uint64) (data []byte, err error) {
	header, err := l.sdk.Node().HeaderByNumberRLP(height)
	if err != nil {
		return
	}
	nextHeader, err := l.sdk.Node().HeaderByNumber(height + 1)
	if err != nil {
		return
	}
	sig, err := nextHeader.GetLastCommitSignature()
	if err != nil {
		return
	}
	bitmap, err := nextHeader.GetLastCommitBitmap()
	if err != nil {
		return
	}
	hs := harmony.HeaderWithSig{header, sig, bitmap}
	data, err = hs.Encode()
	return
}

type Context struct {
	NetworkID int
}

/*
func (l *Listener) SideChain() (sc *side_chain_manager.SideChain, err error) {
	sc = &side_chain_manager.SideChain{
		ChainId: base.HARMONY,
		Name: "harmony",
		BlocksToWait: 1,
	}
	ctx := &Context{}
	if config.CONFIG.Env != "mainnet" {
		ctx.NetworkID = 1
	}
	sc.ExtraInfo, err = json.Marshal(ctx)
	return
}

func (l *Listener) Defer() int {
	return 2
}
*/
