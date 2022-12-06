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

package ont

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology/common"
	vconfig "github.com/ontio/ontology/consensus/vbft/config"
	"github.com/polynetwork/bridge-common/log"
	"time"

	zcom "github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"
	ccom "github.com/ontio/ontology/smartcontract/service/native/cross_chain/common"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/ont"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Listener struct {
	sdk    *ont.SDK
	poly   *zion.SDK
	ccm    string
	ccd    string
	config *config.ListenerConfig
	name   string
}

//
//func (l *Listener) Compose(tx *msg.Tx) error {
//	panic("implement me")
//}

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	if config.ChainId != base.ONT {
		return fmt.Errorf("ONT chain id is incorrect in config %v", config.ChainId)
	}
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.ccm = config.CCMContract
	//l.ccm = outils.CrossChainContractAddress.ToHexString()
	l.poly = poly
	l.sdk, err = ont.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	return
}

//func (l *Listener) getProofHeight(txHeight uint64) (height uint64, err error) {
//	h, err := l.poly.Node().GetSideChainHeight(l.config.ChainId)
//	if err != nil {
//		return 0, fmt.Errorf("getProofHeight unsupported chain %s err %v", l.name, err)
//	}
//	if txHeight >= h {
//		height = txHeight
//	} else {
//		height = h
//	}
//	return
//}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	if tx.SrcHeight == 0 {
		return fmt.Errorf("Invalid tx src height(0)")
	}
	//v, _ := l.poly.Node().GetSideChainMsg(base.ONT, tx.SrcHeight)
	//if len(v) == 0 {
	//	msg, err := l.sdk.Node().GetCrossChainMsg(uint32(tx.SrcHeight))
	//	if err != nil {
	//		return err
	//	}
	//	tx.SrcStateRoot, err = hex.DecodeString(msg)
	//	if err != nil {
	//		return err
	//	}
	//}
	key, err := hex.DecodeString(tx.TxId)
	if err != nil {
		return
	}
	proof, err := l.sdk.Node().GetCrossStatesProof(uint32(tx.SrcHeight), key)
	if err != nil {
		return
	}
	tx.SrcProof, err = hex.DecodeString(proof.AuditPath)
	if err != nil {
		return
	}
	{
		source := common.NewZeroCopySource(tx.SrcProof)
		value, _, _, _ := source.NextVarBytes()

		if len(value) == 0 {
			return fmt.Errorf("ParseAuditPath got null param")
		}
		param := &ccom.MakeTxParam{}
		err = param.Deserialization(common.NewZeroCopySource(value))
		if err != nil {
			return
		}
		tx.Param = &zcom.MakeTxParam{
			TxHash:              param.TxHash,
			CrossChainID:        param.CrossChainID,
			FromContractAddress: param.FromContractAddress,
			ToChainID:           param.ToChainID,
			ToContractAddress:   param.ToContractAddress,
			Method:              param.Method,
			Args:                param.Args,
		}

		rawData, err := msg.EncodeTxParam(tx.Param)
		if err != nil {
			return fmt.Errorf("EncodeTxParam failed. err=%v", err)
		}
		tx.SrcParam = hex.EncodeToString(rawData)
	}
	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	block, err := l.sdk.Node().GetBlockByHeight(uint32(height))
	if err != nil {
		return
	}
	info := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(block.Header.ConsensusPayload, info); err != nil {
		return nil, nil, fmt.Errorf("ONT unmarshal blockInfo error: %s", err)
	}
	if info.NewChainConfig != nil {
		return block.Header.ToArray(), nil, nil
	}
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	events, err := l.sdk.Node().GetSmartContractEventByBlock(uint32(height))
	if err != nil {
		return nil, fmt.Errorf("ONT failed to fetch smart contract events for height %d, err %v", height, err)
	}
	txs = []*msg.Tx{}
	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress != l.ccm {
				continue
			}
			log.Info("ont scan", "height", height, "notify", fmt.Sprintf("%+v", *notify))
			states, ok := notify.States.([]interface{})
			if !ok || states[0].(string) != "makeFromOntProof" {
				continue
			}
			tx := &msg.Tx{
				TxId:       states[4].(string),
				TxType:     msg.SRC,
				SrcHeight:  height,
				SrcChainId: base.ONT,
				SrcHash:    event.TxHash,
				DstChainId: uint64(states[2].(float64)),
			}
			l.Compose(tx)
			txs = append(txs, tx)
		}
	}
	return
}

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	h, err := l.sdk.Node().GetBlockHeightByTxHash(hash)
	height = uint64(h)
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	return
}

func (l *Listener) scanTx(hash string, height uint64) (tx *msg.Tx, err error) {
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

func (l *Listener) LastHeaderSync(force, last uint64) (height uint64, err error) {
	return 0, nil
}

func (l *Listener) LatestHeight() (uint64, error) {
	return l.sdk.Node().GetLatestHeight()
}
