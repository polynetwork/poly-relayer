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

package zilliqa

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Zilliqa/gozilliqa-sdk/provider"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/kardiachain/go-kardia/lib/abi/bind"
	"github.com/maticnetwork/bor/common/hexutil"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/rs/zerolog/log"

	zcom "github.com/devfans/zion-sdk/common"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/msg"
)

// type Listener struct {
// 	*eth.Listener
// 	sdk       *ontevm.SDK
// 	poly      *zion.SDK
// 	name      string
// 	ccm       common.Address
// 	ccd       common.Address
// 	abiParsed abi.ABI
// }

type Listener struct {
	zilSdk         *provider.Provider
	poly           *zion.SDK
	ccm            common.Address
	ccd            common.Address
	config         *config.ListenerConfig
	GetProofHeight func(uint64) (uint64, error)
	GetProof       func([]byte, uint64) (uint64, []byte, error)
	name           string
	abi            abi.ABI
	state          bus.ChainStore // Header sync state
}

// type ZilliqaSyncManager struct {
// 	polySigner               *poly.Account
// 	polySdk                  *poly.PolySdk
// 	relaySyncHeight          uint32
// 	zilAccount               *account.Account
// 	currentHeight            uint64
// 	currentDsBlockNum        uint64
// 	forceHeight              uint64
// 	zilSdk                   *provider.Provider
// 	crossChainManagerAddress string
// 	cfg                      *config.Config
// 	db                       *db.BoltDB
// 	exitChan                 chan int
// 	header4sync              [][]byte
// }

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	if config.ChainId != base.ZILLIQA {
		return fmt.Errorf("Zilliqa chain id is incorrect in config %v", config.ChainId)
	}

	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.ccm = common.HexToAddress(config.CCMContract)
	l.ccd = common.HexToAddress(config.CCDContract)
	l.poly = poly
	// Common
	l.GetProofHeight = l.getProofHeight
	l.GetProof = l.getProof

	l.state = bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: config.ChainId, Type: bus.KEY_HEIGHT_HEADER}, bus.New(config.Bus.Redis),
		config.Bus.HeightUpdateInterval,
	)

	// TODO: make it able to take in multiple nodes
	l.zilSdk = provider.NewProvider(config.Nodes[0])
	return
}

func (l *Listener) getProofHeight(txHeight uint64) (height uint64, err error) {
	abc, err := l.zilSdk.GetBlockchainInfo()
	if err != nil {
		return 0, err
	}
	latestHeight, err := strconv.ParseUint(abc.NumTxBlocks, 10, 64)
	if err != nil {
		return 0, err
	}
	height = latestHeight - 2
	return height, nil
}

func (l *Listener) getProof(txId []byte, txHeight uint64) (height uint64, proof []byte, err error) {
	id := msg.EncodeTxId(txId)
	bytes, err := zcom.MappingKeyAt(id, "01")
	if err != nil {
		err = fmt.Errorf("%s scan event mapping key error %v", l.name, err)
		return
	}
	proofKey := hexutil.Encode(bytes)
	height, err = l.GetProofHeight(txHeight)
	if err != nil {
		err = fmt.Errorf("%s chain get proof height error %v", l.name, err)
		return
	}
	if txHeight > height {
		err = fmt.Errorf("%w Proof not ready tx height %v proof height %v", msg.ERR_PROOF_UNAVAILABLE, txHeight, height)
		// We dont return here, still fetch the proof with tx height
		height = txHeight
	}
	ethProof, e := l.zilSdk.GetStateProof(l.ccd.String(), proofKey, height)
	if e != nil {
		return height, nil, e
	}
	proof, e = json.Marshal(ethProof)
	if e != nil {
		return height, nil, e
	}
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	ccm, err := l.zilSdk.contract
	if err != nil {
		return nil, err
	}
	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}
	events, err := ccm.FilterCrossChainEvent(opt, nil)
	if err != nil {
		return nil, err
	}

	if events == nil {
		return
	}

	txs = []*msg.Tx{}
	for events.Next() {
		ev := events.Event
		param, err := msg.DecodeTxParam(ev.Rawdata)
		if err != nil {
			return nil, err
		}
		log.Info("Found src cross chain tx", "method", param.Method, "hash", ev.Raw.TxHash.String())
		tx := &msg.Tx{
			TxType:     msg.SRC,
			TxId:       msg.EncodeTxId(ev.TxId),
			SrcHash:    ev.Raw.TxHash.String(),
			DstChainId: ev.ToChainId,
			SrcHeight:  height,
			SrcParam:   hex.EncodeToString(ev.Rawdata),
			SrcChainId: l.config.ChainId,
			SrcProxy:   ev.ProxyOrAssetContract.String(),
			DstProxy:   common.BytesToAddress(ev.ToContract).String(),
			SrcAddress: ev.Sender.String(),
		}
		l.Compose(tx)
		txs = append(txs, tx)
	}

	return
}
