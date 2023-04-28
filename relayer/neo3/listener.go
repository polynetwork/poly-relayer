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

package neo3

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/joeqian10/neo3-gogogo/crypto"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/mpt"
	"github.com/joeqian10/neo3-gogogo/rpc/models"
	"github.com/polynetwork/bridge-common/chains/eth"
	"math/big"
	"strconv"
	"time"

	"github.com/joeqian10/neo3-gogogo/block"
	"github.com/joeqian10/neo3-gogogo/io"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/neo3"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

const (
	EMPTY                  = ""
	CROSS_CHAIN_LOCK_EVENT = "CrossChainLockEvent"
)

type Listener struct {
	poly *zion.SDK

	sdk            *neo3.SDK
	neoCcmc        string // neo only has one ccmc, big endian, like: 0x0123456789abcdef0123456789abcdef
	neoConsensus   string // neo next consensus
	neoStateHeight uint64

	config *config.ListenerConfig
	name   string
}

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	if config.ChainId != base.NEO3 {
		return fmt.Errorf("NEO chain id is incorrect in config %v", config.ChainId)
	}
	l.poly = poly
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.sdk, err = neo3.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	l.neoCcmc = config.CCMContract
	err = l.fetchNextConsensus()
	if err != nil {
		return fmt.Errorf("l.fetchNextConsensus error: %v", err)
	}
	return
}

func (l *Listener) fetchNextConsensus() (err error) {
	// the last header synced has the next consensus needed
	lastHeaderSyncHeight, err := l.LastHeaderSync(0, 0)
	if err != nil {
		return fmt.Errorf("l.LastHeaderSync error: %v", err)
	}
	res := l.sdk.Node().GetBlockHeader(strconv.FormatUint(lastHeaderSyncHeight, 10))
	if res.HasError() {
		return fmt.Errorf("GetBlockHeader error: %s", res.GetErrorInfo())
	}
	l.neoConsensus = res.Result.NextConsensus
	return
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {

	var height2 uint64
	if tx.SrcHeight >= l.neoStateHeight {
		height2 = tx.SrcHeight
	} else {
		height2 = l.neoStateHeight
	}
	if height2 == 0 {
		return fmt.Errorf("neo3 Compose: anchor height is zero")
	}
	// get current state height
	res := l.sdk.Node().GetStateHeight()
	if res.HasError() {
		return fmt.Errorf("neo3.GetStateHeight error: %s", res.GetErrorInfo())
	}
	if uint64(res.Result.ValidateRootIndex) < height2 {
		return fmt.Errorf("neo3 state height is too low")
	}

	// get state root
	srGot := false
	var stateRoot *mpt.StateRoot
	for !srGot {
		sr := l.sdk.Node().GetStateRoot(uint32(height2))
		if sr.HasError() {
			return fmt.Errorf("neo3.GetStateRoot error: %s", sr.GetErrorInfo())
		}
		stateRoot = &sr.Result
		if len(stateRoot.Witnesses) == 0 {
			height2++
		} else {
			srGot = true
			l.neoStateHeight = height2 // next tx can start from this height to get state root
			tx.SrcProofHeight = height2
		}
	}
	buff := io.NewBufBinaryWriter()
	stateRoot.Serialize(buff.BinaryWriter)
	tx.SrcStateRoot = buff.Bytes()

	// get proof
	storeKey := crypto.Base64Encode(helper.HexToBytes(tx.TxId))
	pf := l.sdk.Node().GetProof(stateRoot.RootHash, l.neoCcmc, storeKey)

	if pf.HasError() {
		return fmt.Errorf("neo3.GetProof error: %s", pf.GetErrorInfo())
	}
	proof, err := crypto.Base64Decode(pf.Result)
	if err != nil {
		return fmt.Errorf("neo3.Base64Decode proof error: %v", err)
	}
	tx.SrcProof = proof
	err = l.ParseParam(tx)
	return
}

func (l *Listener) ParseParam(tx *msg.Tx) error {
	stateRoot := &mpt.StateRoot{}
	br := io.NewBinaryReaderFromBuf(tx.SrcStateRoot)
	stateRoot.Deserialize(br)
	if br.Err != nil {
		return fmt.Errorf("neo3.StateRoot.Deserialize error: %v", br.Err)
	}

	contractId, key, proofs, err := mpt.ResolveProof(tx.SrcProof)
	if err != nil {
		return fmt.Errorf("neo3.mpt.ResolveProof error: %v", err)
	}
	root, _ := helper.UInt256FromString(stateRoot.RootHash)
	value, err := mpt.VerifyProof(root, contractId, key, proofs)
	if err != nil {
		return fmt.Errorf("neo3.mpt.VerifyProof error: %v", err)
	}
	neoParam, err := DeserializeCrossChainTxParameter(value)
	if err != nil {
		return fmt.Errorf("neo3.DeserializeCrossChainTxParameter error: %v", err)
	}
	tx.Param = convertNeoParamToEthParam(neoParam)
	paramData, err := msg.EncodeTxParam(tx.Param)
	if err != nil {
		return fmt.Errorf("neo3 EncodeTxParam error: %v", err)
	}
	tx.SrcParam = hex.EncodeToString(paramData)

	return nil
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	res := l.sdk.Node().GetBlockHeader(strconv.FormatUint(height, 10))
	if res.HasError() {
		return nil, nil, fmt.Errorf("GetBlockHeader error: %s", res.GetErrorInfo())
	}
	if res.Result.Hash == EMPTY {
		return nil, nil, fmt.Errorf("GetBlockHeader error: empty response")
	}
	if res.Result.NextConsensus == l.neoConsensus {
		return nil, nil, nil
	}

	h, err := block.NewBlockHeaderFromRPC(&res.Result)
	if err != nil {
		return nil, nil, err
	}
	buf := io.NewBufBinaryWriter()
	h.Serialize(buf.BinaryWriter)
	log.Info("Fetched neo block header", "height", height, "hash", res.Result.Hash)
	// finally, set the next consensus to this block's NextConsensus
	l.neoConsensus = res.Result.NextConsensus
	return buf.Bytes(), h.GetHash().ToByteArray(), nil
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	res := l.sdk.Node().GetBlock(strconv.FormatUint(height, 10))
	if res.HasError() {
		err = fmt.Errorf("neo3.GetBlock error: %s", res.GetErrorInfo())
		return
	}
	if res.Result.Hash == EMPTY {
		err = fmt.Errorf("neo3.GetBlock error: empty response")
		return
	}

	txs = []*msg.Tx{}
	for _, trx := range res.Result.Tx {
		tt, err := l.ScanTx(trx.Hash)
		if err != nil {
			return nil, err
		}
		if tt != nil {
			txs = append(txs, tt)
		}
	}
	return
}

func (l *Listener) BatchScan(start, end uint64) ([]*msg.Tx, error) {
	return nil, nil
}

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	res := l.sdk.Node().GetTransactionHeight(hash)
	if res.HasError() {
		err = fmt.Errorf("GetTransactionHeight error: %s", res.GetErrorInfo())
		return
	}
	height = uint64(res.Result)
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	res := l.sdk.Node().GetApplicationLog(hash)
	if res.HasError() {
		return nil, fmt.Errorf("neo3.GetApplicationLog error: %s", res.GetErrorInfo())
	}
	if res.Result.TxId == EMPTY {
		return nil, fmt.Errorf("neo3.GetApplicationLog error: empty response")
	}

	height, err := l.GetTxBlock(hash)
	if err != nil {
		return nil, fmt.Errorf("neo3.GetTxBlock error: %v", err)
	}

	for _, execution := range res.Result.Executions {
		if execution.VMState == "FAULT" {
			return
		}
		for _, notification := range execution.Notifications {
			u, _ := helper.UInt160FromString(notification.Contract)
			if "0x"+u.String() == l.neoCcmc && notification.EventName == CROSS_CHAIN_LOCK_EVENT {
				if notification.State.Type != "Array" {
					return nil, fmt.Errorf("notification.State.Type error: Type is not Array")
				}
				states := models.ConvertInvokeStackArray(notification.State) // only convert "Array" type InvokeStack
				if len(states) != 5 {                                        // CrossChainLockEvent(caller, para.fromContract, toChainID, resquestKey, para.args);
					return nil, fmt.Errorf("notification.State.Value error: Wrong length of states")
				}

				var toChainId *big.Int
				if states[2].Type == "Integer" {
					toChainId, _ = new(big.Int).SetString(states[2].Value.(string), 10)
				} else { // ByteString
					raw, err := crypto.Base64Decode(states[2].Value.(string))
					if err != nil {
						return nil, fmt.Errorf("Base64Decode toChainId error: %v", err)
					}
					toChainId = new(big.Int).SetBytes(raw)
				}
				// get key
				key := states[3].Value.(string)       // base64 string for storeKey: 0102 + toChainId + toRequestId, like 01020501
				temp, err := crypto.Base64Decode(key) // base64 encoded
				if err != nil {
					return nil, fmt.Errorf("crypto.Base64Decode key error: %v", err)
				}
				// get the neo chain synced height on zion
				latestSyncHeight, err := l.LastHeaderSync(0, 0)
				if err != nil {
					return nil, fmt.Errorf("LastHeaderSync error: %s", err)
				}
				var usedHeight uint64
				if height >= latestSyncHeight {
					usedHeight = height
				} else {
					usedHeight = latestSyncHeight
				}

				key = helper.BytesToHex(temp)
				tx := &msg.Tx{
					TxId:       key,
					TxType:     msg.SRC,
					SrcHash:    hash,
					SrcHeight:  usedHeight,
					SrcChainId: l.config.ChainId,
					DstChainId: toChainId.Uint64(),
				}
				err = l.Compose(tx)
				if err != nil {
					log.Error("neo3 Compose tx failed", "height", usedHeight, "src hash", hash, "err", err)
					return nil, err
				}
				return tx, nil
			}
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

// not used
func (l *Listener) L1Node() *eth.Client {
	return nil
}

func (l *Listener) ChainId() uint64 {
	return l.config.ChainId
}

func (l *Listener) Defer() int {
	if l.config.Defer > 0 {
		return l.config.Defer
	}
	return 1
}

func (l *Listener) LastHeaderSync(force, last uint64) (height uint64, err error) {
	if l.poly == nil {
		err = fmt.Errorf("no zion sdk is provided for GetInfoHeight")
		return
	}
	h, err := l.poly.Node().GetInfoHeight(nil, l.config.ChainId)
	if err != nil {
		return
	}
	height = uint64(h)
	if last > height {
		height = last
	}
	if force != 0 {
		return force, nil
	}
	return
}

func (l *Listener) LatestHeight() (uint64, error) {
	return l.sdk.Node().GetLatestHeight()
}

func (l *Listener) WaitTillHeight(ctx context.Context, height uint64, interval time.Duration) (uint64, bool) {
	// not used
	return 0, false
}
