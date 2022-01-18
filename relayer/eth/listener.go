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

package eth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/eth"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	pcom "github.com/polynetwork/poly/common"
	ccom "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	ceth "github.com/polynetwork/poly/native/service/cross_chain_manager/eth"
)

type Listener struct {
	sdk            *eth.SDK
	poly           *poly.SDK
	ccm            common.Address
	ccd            common.Address
	config         *config.ListenerConfig
	GetProofHeight func(uint64) (uint64, error)
	GetProof       func([]byte, uint64) (uint64, []byte, error)
	name           string
	state          bus.ChainStore // Header sync state
}

func (l *Listener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
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

	l.sdk, err = eth.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	return
}

func (l *Listener) getProofHeight(txHeight uint64) (height uint64, err error) {
	switch l.config.ChainId {
	case base.ETH, base.BSC, base.HECO, base.O3, base.MATIC, base.PIXIE:
		h, err := l.poly.Node().GetSideChainHeight(l.config.ChainId)
		if err != nil {
			return 0, err
		}
		height = h - base.BlocksToWait(l.config.ChainId)
	case base.OK:
		height, _ = l.state.GetHeight(context.Background())
		if height > 0 {
			return
		}
		height, err = l.sdk.Node().GetLatestHeight()
		if err != nil {
			return 0, err
		}
		height = height - 2
	case base.PLT:
		return txHeight, nil
	default:
		return 0, fmt.Errorf("getProofHeight unsupported chain %s", l.name)
	}
	return
}

func (l *Listener) getProof(txId []byte, txHeight uint64) (height uint64, proof []byte, err error) {
	id := msg.EncodeTxId(txId)
	bytes, err := ceth.MappingKeyAt(id, "01")
	if err != nil {
		err = fmt.Errorf("%s scan event mapping key error %v", l.name, err)
		return
	}
	proofKey := hexutil.Encode(bytes)
	height, err = l.GetProofHeight(txHeight)
	if err != nil {
		err = fmt.Errorf("%s can height get proof height error %v", l.name, err)
		return
	}
	if txHeight > height {
		err = fmt.Errorf("%w Proof not ready tx height %v proof height %v", msg.ERR_PROOF_UNAVAILABLE, txHeight, height)
		// We dont return here, still fetch the proof with tx height
		height = txHeight
	}
	ethProof, e := l.sdk.Node().GetProof(l.ccd.String(), proofKey, height)
	if e != nil {
		return height, nil, e
	}
	proof, e = json.Marshal(ethProof)
	if e != nil {
		return height, nil, e
	}
	return
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	if len(tx.SrcProofHex) > 0 && tx.Param != nil { // Already fetched the proof
		log.Info("Proof already fetched for tx", "hash", tx.SrcHash)
		tx.SrcProof, _ = hex.DecodeString(tx.SrcProofHex)
		return
	}

	if tx.SrcHeight == 0 || len(tx.TxId) == 0 {
		return fmt.Errorf("tx missing attributes src height %v, txid %s", tx.SrcHeight, tx.TxId)
	}
	if len(tx.SrcParam) == 0 {
		return fmt.Errorf("src param is missing")
	}
	event, err := hex.DecodeString(tx.SrcParam)
	if err != nil {
		return fmt.Errorf("%s submitter decode src param error %v event %s", l.name, err, tx.SrcParam)
	}
	txId, err := hex.DecodeString(tx.TxId)
	if err != nil {
		return fmt.Errorf("%s failed to decode src txid %s, err %v", l.name, tx.TxId, err)
	}
	param := &ccom.MakeTxParam{}
	err = param.Deserialization(pcom.NewZeroCopySource(event))
	if err != nil {
		return
	}
	tx.Param = param
	tx.SrcEvent = event
	tx.SrcProofHeight, tx.SrcProof, err = l.GetProof(txId, tx.SrcHeight)
	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	hdr, err := l.sdk.Node().HeaderByNumber(context.Background(), big.NewInt(int64(height)))
	if err != nil {
		err = fmt.Errorf("Fetch block header error %v", err)
		return nil, nil, err
	}
	log.Info("Fetched block header", "chain", l.name, "height", height, "hash", hdr.Hash().String())
	hash = hdr.Hash().Bytes()
	header, err = hdr.MarshalJSON()
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	ccm, err := eccm_abi.NewEthCrossChainManager(l.ccm, l.sdk.Node())
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
		param := &ccom.MakeTxParam{}
		err = param.Deserialization(pcom.NewZeroCopySource([]byte(ev.Rawdata)))
		if err != nil {
			return
		}
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

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	receipt, err := l.sdk.Node().TransactionReceipt(context.Background(), common.HexToHash(hash))
	if err != nil {
		return
	}
	height = uint64(receipt.BlockNumber.Int64())
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	return
}

func (l *Listener) ListenCheck() time.Duration {
	duration := time.Second
	if l.config.ListenCheck > 0 {
		duration = time.Duration(l.config.ListenCheck) * time.Second
	}
	return duration
}

func (l *Listener) Nodes() chains.Nodes {
	return l.sdk.ChainSDK
}

func (l *Listener) ChainId() uint64 {
	return l.config.ChainId
}

func (l *Listener) Defer() int {
	return l.config.Defer
}

func (l *Listener) Name() string {
	return l.name
}

func (l *Listener) SDK() *eth.SDK {
	return l.sdk
}

func (l *Listener) LatestHeight() (uint64, error) {
	return l.sdk.Node().GetLatestHeight()
}

func (l *Listener) LastHeaderSync(force, last uint64) (height uint64, err error) {
	if l.poly == nil {
		err = fmt.Errorf("No poly sdk provided for listener", "chain", l.name)
		return
	}

	if force != 0 {
		return force, nil
	}
	return l.poly.Node().GetSideChainHeight(l.config.ChainId)
}
