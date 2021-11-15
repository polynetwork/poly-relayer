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

package ok

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store/rootmulti"
	ethcom "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gogo/protobuf/proto"
	"github.com/tendermint/tendermint/crypto/merkle"

	ccom "github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/ok"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/polynetwork/poly/common"
	pcom "github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/native/service/cross_chain_manager/okex"
	okex2 "github.com/polynetwork/poly/native/service/header_sync/okex"

	"github.com/polynetwork/poly/native/service/header_sync/cosmos"
)

type Listener struct {
	*eth.Listener
	tm    *ok.SDK
	codec *codec.Codec
}

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	l.Listener = new(eth.Listener)
	err = l.Listener.Init(config, poly)
	if err != nil {
		return
	}
	l.codec = okex2.NewCDC()
	l.tm, err = ok.WithOptions(base.OK, config.ExtraNodes, time.Minute, 1)
	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	cr, err := l.tm.Node().Tendermint().QueryCommitResult(int64(height))
	if err != nil {
		err = fmt.Errorf("OKex query commit result height %d error %v", height, err)
		return
	}
	if !bytes.Equal(cr.Header.ValidatorsHash, cr.Header.NextValidatorsHash) {
		vs, err := l.tm.Node().GetValidators(height)
		if err != nil {
			err = fmt.Errorf("OKex get validators height %d error %v", height, err)
			return nil, nil, err
		}
		hdr := cosmos.CosmosHeader{
			Header:  *cr.Header,
			Commit:  cr.Commit,
			Valsets: vs,
		}
		header, err = l.codec.MarshalBinaryBare(hdr)
		if err != nil {
			err = fmt.Errorf("OKex header marshal binary height %d, err %v", height, err)
		}
		return header, nil, err
	}
	return
}

func (l *Listener) LastHeaderSync(force, last uint64) (height uint64, err error) {
	if l.Poly() == nil {
		err = fmt.Errorf("No poly sdk provided for listener", "chain", l.ChainId())
		return
	}

	if force != 0 {
		return force, nil
	}
	epoch, err := l.Poly().Node().GetSideChainEpoch(l.ChainId())
	if err != nil {
		return
	}

	info := &cosmos.CosmosEpochSwitchInfo{}
	err = info.Deserialization(common.NewZeroCopySource(epoch))
	if err != nil {
		return
	}
	height = uint64(info.Height)
	if last > height {
		height = last
	}
	return
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	if tx.SrcHeight == 0 || len(tx.TxId) == 0 {
		return fmt.Errorf("tx missing attributes src height %v, txid %s", tx.SrcHeight, tx.TxId)
	}
	if len(tx.SrcParam) == 0 {
		return fmt.Errorf("src param is missing")
	}
	event, err := hex.DecodeString(tx.SrcParam)
	if err != nil {
		return fmt.Errorf("%v submitter decode src param error %v event %s", l.ChainId(), err, tx.SrcParam)
	}
	txId, err := hex.DecodeString(tx.TxId)
	if err != nil {
		return fmt.Errorf("%v failed to decode src txid %s, err %v", l.ChainId(), tx.TxId, err)
	}
	param := &ccom.MakeTxParam{}
	err = param.Deserialization(pcom.NewZeroCopySource(event))
	if err != nil {
		return
	}
	tx.Param = param

	height, proof, err := l.FetchProof(txId, tx.SrcHeight)
	if err != nil {
		return fmt.Errorf("OK chain fetch proof error %v", err)
	}
	tx.SrcProofHeight = height + 1
	var mp merkle.Proof
	err = proto.UnmarshalText(proof.StorageProofs[0].Proof[0], &mp)
	if err != nil {
		return
	}
	path := "/"
	for i := range mp.Ops {
		op := mp.Ops[len(mp.Ops)-1-i]
		path += "x:" + hex.EncodeToString(op.Key)
		path += "/"
	}
	keyPath := strings.TrimSuffix(path, "/")
	tx.SrcEvent, err = l.codec.MarshalBinaryBare(&okex.CosmosProofValue{
		Kp:    keyPath,
		Value: event,
	})
	if err != nil {
		return
	}
	cr, err := l.tm.Node().Tendermint().QueryCommitResult(int64(tx.SrcProofHeight))
	if err != nil {
		return
	}
	vs, err := l.tm.Node().GetValidators(tx.SrcProofHeight)
	if err != nil {
		return
	}
	tx.SrcStateRoot, err = l.codec.MarshalBinaryBare(&okex2.CosmosHeader{
		Header:  *cr.Header,
		Commit:  cr.Commit,
		Valsets: vs,
	})
	if err != nil {
		return
	}

	err = l.verifyMerkleProof(&mp)
	if err != nil {
		return
	}

	prt := rootmulti.DefaultProofRuntime()
	err = prt.VerifyValue(&mp, cr.AppHash, keyPath, crypto.Keccak256(event))
	if err != nil {
		log.Fatal("Unexpected proof verify error", "err", err, "mp", util.Verbose(mp), "path", keyPath, "event", tx.SrcParam)
		return
	}
	tx.SrcProof, err = l.codec.MarshalBinaryBare(mp)
	if err != nil {
		return
	}
	return
}

func (l *Listener) verifyMerkleProof(mp *merkle.Proof) (err error) {
	if len(mp.Ops) != 2 {
		return fmt.Errorf("proof ops size is not 2")
	}
	if len(mp.Ops[0].Key) != 1+ethcom.HashLength+ethcom.AddressLength {
		return fmt.Errorf("mp.Ops[0].Key incorrect size %v", mp.Ops[0].Key)
	}

	if !bytes.HasPrefix(mp.Ops[0].Key, append([]byte{5}, l.ECCD().Bytes()...)) {
		return fmt.Errorf("Invalid mp.Ops[0].Key %x", mp.Ops[0].Key)
	}
	if !bytes.Equal(mp.Ops[1].Key, []byte("evm")) {
		return fmt.Errorf("Invalid mp.Ops[1].Key %x", mp.Ops[1].Key)
	}
	return
}
