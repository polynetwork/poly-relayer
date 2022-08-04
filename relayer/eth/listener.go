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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"strings"

	"math/big"
	"time"

	zcom "github.com/devfans/zion-sdk/common"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/polynetwork/bridge-common/abi/lock_proxy_abi"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/eth"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/tools"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Listener struct {
	sdk            *eth.SDK
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

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
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
	if err == nil {
		l.abi, err = abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerImplementationABI))
	}
	return
}

func (l *Listener) getProofHeight(txHeight uint64) (height uint64, err error) {
	switch l.config.ChainId {
	case base.ETH, base.BSC, base.HECO, base.O3, base.MATIC, base.BYTOM, base.HSC:
		h, err := l.poly.Node().GetInfoHeight(nil, l.config.ChainId)
		height = uint64(h)
		return height, err
	case base.OK, base.HARMONY:
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
	bytes, err := zcom.MappingKeyAt(id, "01")
	if err != nil {
		err = fmt.Errorf("%s scan event mapping key error %v", l.name, err)
		return
	}
	proofKey := hexutil.Encode(bytes)
	height, err = l.GetProofHeight(txHeight)
	log.Info("GetProofHeight", "height", height, "chain", l.ChainId())
	if err != nil {
		err = fmt.Errorf("%s chain get proof height error %v", l.name, err)
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
	param, err := msg.DecodeTxParam(event)
	if err != nil {
		return
	}
	tx.Param = param
	tx.SrcEvent = event
	tx.SrcProofHeight, tx.SrcProof, err = l.GetProof(txId, tx.SrcHeight)
	if err != nil {
		return
	}
	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	lastHeaderSyncHeight, err := l.LastHeaderSync(0, 0)
	if height <= lastHeaderSyncHeight {
		log.Warn("Header already synced to zion", "height", height, "lastHeaderSyncHeight", lastHeaderSyncHeight, "chain", l.name)
		return nil, nil, nil
	}

	fetchHeader := (height-lastHeaderSyncHeight)%l.config.HeaderSyncInterval == 0
	if !fetchHeader {
		ccmContract, err := eccm_abi.NewEthCrossChainManagerImplementation(l.ccm, l.sdk.Node())
		if err != nil {
			return nil, nil, fmt.Errorf("NewEthCrossChainManagerImplemetation error %v", err)
		}
		opt := &bind.FilterOpts{
			Start:   height,
			End:     &height,
			Context: context.Background(),
		}
		crossChainEvents, err := ccmContract.FilterCrossChainEvent(opt, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("FilterCrossChainEvent error %v", err)
		}
		if crossChainEvents != nil && crossChainEvents.Next() {
			fetchHeader = true
			log.Info("Found cross chain events", "chain", l.name, "height", height)
		}
	}
	if !fetchHeader {
		return nil, nil, nil
	}

	hdr, err := l.sdk.Node().GetHeader(height)
	if err != nil {
		err = fmt.Errorf("Fetch block header error %v", err)
		return nil, nil, err
	}

	root := &struct {
		Root common.Hash `json:"stateRoot"        gencodec:"required"`
	}{}
	err = json.Unmarshal(hdr, root)
	if err != nil {
		return nil, nil, err
	}
	header, err = json.Marshal(root)
	if err != nil {
		return nil, nil, err
	}
	log.Info("Fetched block header", "chain", l.name, "height", height, "Root", root.Root.Hex())
	return
}

func (l *Listener) GetHeader(height uint64) (header []byte, hash []byte, err error) {
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

func (l *Listener) ScanDst(height uint64) (txs []*msg.Tx, err error) {
	ccm, err := eccm_abi.NewEthCrossChainManagerImplementation(l.ccm, l.sdk.Node())
	if err != nil {
		return nil, err
	}
	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}
	events, err := ccm.FilterVerifyHeaderAndExecuteTxEvent(opt)
	if err != nil {
		return nil, err
	}

	if events == nil {
		return
	}

	txs = []*msg.Tx{}
	for events.Next() {
		ev := events.Event
		tx := &msg.Tx{
			DstChainId: l.ChainId(),
			DstHash:    ev.Raw.TxHash.String(),
			SrcChainId: ev.FromChainID,
			DstProxy:   hex.EncodeToString(ev.ToContract),
			DstHeight:  ev.Raw.BlockNumber,
			PolyHash:   common.BytesToHash(ev.CrossChainTxHash),
		}
		txs = append(txs, tx)
	}
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	ccm, err := eccm_abi.NewEthCrossChainManagerImplementation(l.ccm, l.sdk.Node())
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

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	receipt, err := l.sdk.Node().TransactionReceipt(context.Background(), common.HexToHash(hash))
	if err != nil {
		return
	}
	height = uint64(receipt.BlockNumber.Int64())
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	res, err := l.sdk.Node().TransactionReceipt(context.Background(), msg.HexToHash(hash))
	if err != nil || res == nil {
		return
	}
	for _, entry := range res.Logs {
		ev := new(eccm_abi.EthCrossChainManagerImplementationCrossChainEvent)
		if msg.FilterLog(l.abi, l.ccm, "CrossChainEvent", entry, ev) {
			param, err := msg.DecodeTxParam(ev.Rawdata)
			if err != nil {
				return nil, err
			}
			log.Info("Found src cross chain tx", "method", param.Method, "hash", ev.Raw.TxHash.String())
			tx := &msg.Tx{
				TxType:     msg.SRC,
				TxId:       msg.EncodeTxId(ev.TxId),
				SrcHash:    hash,
				DstChainId: ev.ToChainId,
				SrcHeight:  res.BlockNumber.Uint64(),
				SrcParam:   hex.EncodeToString(ev.Rawdata),
				SrcChainId: l.config.ChainId,
				SrcProxy:   ev.ProxyOrAssetContract.String(),
				DstProxy:   common.BytesToAddress(ev.ToContract).String(),
				SrcAddress: ev.Sender.String(),
			}
			l.Compose(tx)
			// Only the first?
			return tx, nil
		}
	}
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
		err = fmt.Errorf("No poly sdk provided for listener chain %s", l.name)
		return
	}

	if force != 0 {
		return force, nil
	}
	h, err := l.poly.Node().GetInfoHeight(nil, l.config.ChainId)
	height = uint64(h)
	return
}

func (l *Listener) Validate(tx *msg.Tx) (err error) {
	txId, err := hex.DecodeString(tx.TxId)
	if err != nil {
		return fmt.Errorf("%s failed to decode src txid %s, err %v", l.name, tx.TxId, err)
	}
	id := msg.EncodeTxId(txId)
	key, err := zcom.MappingKeyAt(id, "01")
	if err != nil {
		err = fmt.Errorf("%s scan event mapping key error %v", l.name, err)
		return
	}

	proof, err := l.sdk.Node().StorageAt(nil, l.ccd, common.BytesToHash(key), nil)
	if err != nil {
		return fmt.Errorf("get proof storage failure %v", err)
	}

	value, err := msg.EncodeTxParam(tx.MerkleValue.MakeTxParam)
	if err == nil {
		if bytes.Equal(proof, crypto.Keccak256(value)) {
			log.Info("Validated proof for poly tx", "hash", tx.PolyHash, "src_chain", l.ChainId())
			return
		}
	}
	err = fmt.Errorf("%w CheckProofResult failed, hash doesnt match", msg.ERR_TX_VOILATION)
	return
}

func (l *Listener) ScanEvents(height uint64, ch chan tools.CardEvent) (err error) {
	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}

	events := []tools.CardEvent{}
	for _, address := range l.config.LockProxyContract {
		p, err := lock_proxy_abi.NewLockProxy(common.HexToAddress(address), l.sdk.Node().Client)
		if err != nil {
			return err
		}

		setManagerProxyEvents, err := p.FilterSetManagerProxyEvent(opt)
		if err != nil {
			return err
		}
		bindProxyEvents, err := p.FilterBindProxyEvent(opt)
		if err != nil {
			return err
		}
		bindAssetEvents, err := p.FilterBindAssetEvent(opt)
		if err != nil {
			return err
		}
		for setManagerProxyEvents.Next() {
			ev := setManagerProxyEvents.Event
			events = append(events, &msg.SetManagerProxyEvent{
				TxHash:   ev.Raw.TxHash.String()[2:],
				Contract: ev.Raw.Address.String(),
				ChainId:  l.ChainId(),
				Manager:  ev.Manager.String(),
			})
		}

		for bindProxyEvents.Next() {
			ev := bindProxyEvents.Event
			events = append(events, &msg.BindProxyEvent{
				TxHash:    ev.Raw.TxHash.String()[2:],
				Contract:  ev.Raw.Address.String(),
				ChainId:   l.ChainId(),
				ToChainId: ev.ToChainId,
				ToProxy:   hex.EncodeToString(ev.TargetProxyHash),
			})
		}

		for bindAssetEvents.Next() {
			ev := bindAssetEvents.Event
			events = append(events, &msg.BindAssetEvent{
				TxHash:        ev.Raw.TxHash.String()[2:],
				Contract:      ev.Raw.Address.String(),
				ChainId:       l.ChainId(),
				FromAsset:     ev.FromAssetHash.String(),
				ToChainId:     ev.ToChainId,
				Asset:         hex.EncodeToString(ev.TargetProxyHash),
				InitialAmount: ev.InitialAmount,
			})
		}
	}

	for _, ev := range events {
		ch <- ev
	}
	return
}
