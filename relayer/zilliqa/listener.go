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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Zilliqa/gozilliqa-sdk/bech32"
	"github.com/Zilliqa/gozilliqa-sdk/provider"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"

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
	heightStr := strconv.FormatUint(height, 10)
	ethProof, e := l.zilSdk.GetStateProof(l.ccd.String(), proofKey, &heightStr)
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
	// ccm, err := l.zilSdk.contract
	transactions, err := l.zilSdk.GetTxnBodiesForTxBlock(strconv.FormatUint(height, 10))
	if err != nil {
		return nil, err
	}
	if err != nil {
		if strings.Contains(err.Error(), "TxBlock has no transactions") {
			log.Info("ZilliqaSyncManager no transaction in block %d\n", height)
			return nil, nil
		} else {
			log.Info("ZilliqaSyncManager get transactions for tx block %d failed: %s\n", height, err.Error())
			return nil, err
		}
	}

	for _, zilTx := range transactions {
		if !zilTx.Receipt.Success {
			continue
		}
		tx, err := l.ScanTx(zilTx.ID)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return
}

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	// receipt, err := l.zilSdk.GetTransaction(hash)
	// if err != nil {
	// 	return
	// }
	// TODO: get height
	height = 12
	// height = uint64(receipt.BlockNumber.Int64())
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	res, err := l.zilSdk.GetTransaction(hash)
	if err != nil || res == nil {
		return
	}
	eventLogs := res.Receipt.EventLogs

	for _, event := range eventLogs {
		toAddr, _ := bech32.ToBech32Address(event.Address)
		if toAddr == l.config.CCMContract {
			if event.EventName != "CrossChainEvent" {
				continue
			}
			ev := new(eccm_abi.EthCrossChainManagerImplementationCrossChainEvent)
			param, err := msg.DecodeTxParam(ev.Rawdata)
			if err != nil {
				return nil, err
			}
			log.Info("Found src cross chain tx", "method", param.Method, "hash", param.TxHash)
			tx := &msg.Tx{
				TxType:     msg.SRC,
				TxId:       msg.EncodeTxId(ev.TxId),
				SrcHash:    hash,
				DstChainId: ev.ToChainId,
				// TODO: get srcheight
				SrcHeight:  1,
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

func (l *Listener) ListenCheck() time.Duration {
	duration := time.Second
	if l.config.ListenCheck > 0 {
		duration = time.Duration(l.config.ListenCheck) * time.Second
	}
	return duration
}

func (l *Listener) Nodes() chains.Nodes {
	// TODO:
	return nil
}

func (l *Listener) ChainId() uint64 {
	return l.config.ChainId
}

func (l *Listener) Defer() int {
	return l.config.Defer
}

func (l *Listener) LatestHeight() (uint64, error) {
	abc, err := l.zilSdk.GetBlockchainInfo()
	if err != nil {
		return 0, err
	}
	latestHeight, err := strconv.ParseUint(abc.NumTxBlocks, 10, 64)
	if err != nil {
		return 0, err
	}
	return latestHeight, nil
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	// TODO:
	return
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