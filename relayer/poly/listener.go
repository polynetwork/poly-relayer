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

package poly

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/rlp"

	zcom "github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"
	ccm "github.com/devfans/zion-sdk/contracts/native/go_abi/cross_chain_manager_abi"
	"github.com/devfans/zion-sdk/contracts/native/governance/node_manager"
	"github.com/devfans/zion-sdk/core/types"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Listener struct {
	sdk       *zion.SDK
	config    *config.ListenerConfig
	lastEpoch uint64
}

func (l *Listener) Init(config *config.ListenerConfig, sdk *zion.SDK) (err error) {
	l.config = config
	if sdk != nil {
		l.sdk = sdk
	} else {
		l.sdk, err = zion.WithOptions(base.POLY, config.Nodes, time.Minute, 1)
	}
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	ccm, err := ccm.NewCrossChainManager(zion.CCM_ADDRESS, l.sdk.Node())
	if err != nil {
		return nil, err
	}
	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}
	events, err := ccm.FilterMakeProof(opt)
	if err != nil {
		return nil, err
	}

	if events == nil {
		return
	}

	txs = []*msg.Tx{}
	for events.Next() {
		ev := events.Event
		param := new(zcom.ToMerkleValue)
		value, err := hex.DecodeString(ev.MerkleValueHex)
		if err != nil {
			return nil, err
		}
		err = rlp.DecodeBytes(value, param)
		/*
			err = param.Deserialization(pcom.NewZeroCopySource(value))
		*/
		if err != nil {
			err = fmt.Errorf("rlp decode poly merkle value error %v", err)
			return nil, err
		}

		tx := new(msg.Tx)
		tx.MerkleValue = param
		tx.PolyParam = ev.MerkleValueHex
		tx.DstChainId = param.MakeTxParam.ToChainID
		tx.SrcProxy = hex.EncodeToString(param.MakeTxParam.FromContractAddress)
		tx.DstProxy = hex.EncodeToString(param.MakeTxParam.ToContractAddress)
		tx.PolyKey = ev.Key
		tx.PolyHeight = height
		tx.PolyHash = ev.Raw.TxHash
		tx.TxType = msg.POLY
		tx.TxId = hex.EncodeToString(param.MakeTxParam.CrossChainID)
		tx.SrcChainId = param.FromChainID
		/*
			switch tx.SrcChainId {
			case base.NEO, base.ONT:
				tx.TxId = util.ReverseHex(tx.TxId)
			}
		*/
		txs = append(txs, tx)
	}

	return
}

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	h, err := l.sdk.Node().GetBlockHeightByTxHash(msg.Hash(hash))
	height = uint64(h)
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	return
}

func (l *Listener) ChainId() uint64 {
	return base.POLY
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	return
}

func (l *Listener) Defer() int {
	return 1
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

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	return
}

func (l *Listener) Epoch(height uint64) (info *msg.PolyEpoch, err error) {
	epoch, err := l.sdk.Node().GetEpochInfo(height)
	if err != nil {
		return
	}
	if epoch.Status != node_manager.ProposalStatusPassed {
		return
	}
	if epoch.ID == l.lastEpoch {
		return
	}

	info = &msg.PolyEpoch{
		EpochId: epoch.ID,
		Height:  height,
	}
	header, err := l.sdk.Node().HeaderByNumber(context.Background(), big.NewInt(int64(height)))
	if err != nil {
		return nil, err
	}
	info.Header, err = rlp.EncodeToBytes(types.HotstuffFilteredHeader(header, false))
	if err != nil {
		return nil, err
	}
	extra, err := types.ExtractHotstuffExtra(header)
	if err != nil {
		return
	}
	info.Seal, err = rlp.EncodeToBytes(extra.CommittedSeal)
	if err != nil {
		return
	}

	proof, err := l.sdk.Node().GetProof(zion.NODE_MANAGER_ADDRESS.Hex(), zion.EpochProofKey(epoch.ID).Hex(), height)
	if err != nil {
		return
	}
	info.AccountProof, err = msg.RlpEncodeStrings(proof.AccountProof)
	if err != nil {
		err = fmt.Errorf("rlp encode poly epoch account proof failed", "epoch", epoch.ID, "err", err)
		return
	}
	if len(proof.StorageProofs) == 0 {
		err = fmt.Errorf("Failed to fetch poly epoch storage proof, got empty", "epoch", epoch.ID)
		return
	}
	info.StorageProof, err = msg.RlpEncodeStrings(proof.StorageProofs[0].Proof)
	if err != nil {
		err = fmt.Errorf("rlp encode poly storage proof failed", "epoch", epoch.ID, "err", err)
		return
	}
	info.Epoch, err = msg.RlpEncodeEpoch(epoch.ID, epoch.StartHeight, epoch.Peers)
	if err != nil {
		return
	}
	l.lastEpoch = epoch.ID
	return
}

func (l *Listener) LastHeaderSync(force uint64, last uint64) (uint64, error) {
	if force != 0 {
		return force, nil
	}
	if last == 0 {
		last = 1
	}
	return last, nil
}
