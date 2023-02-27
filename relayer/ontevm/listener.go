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

package ontevm

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ontocommon "github.com/ontio/ontology/common"
	ccom "github.com/ontio/ontology/smartcontract/service/native/cross_chain/common"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/ontevm"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"strings"
	"time"
)

type Listener struct {
	*eth.Listener
	sdk       *ontevm.SDK
	poly      *zion.SDK
	name      string
	ccm       common.Address
	ccd       common.Address
	abiParsed abi.ABI
}

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	if config.ChainId != base.ONTEVM {
		return fmt.Errorf("ONTEVM chain id is incorrect in config %v", config.ChainId)
	}

	l.Listener = new(eth.Listener)
	l.poly = poly
	err = l.Listener.Init(config, poly)
	if err != nil {
		return
	}

	l.name = base.GetChainName(config.ChainId)
	l.ccm = common.HexToAddress(config.CCMContract)
	l.ccd = common.HexToAddress(config.CCDContract)

	l.sdk, err = ontevm.WithOptions(config.ChainId, config.ExtraNodes, time.Minute, 1)
	if err != nil {
		return fmt.Errorf("ontevm.WithOptions err:%v", err)
	}

	l.abiParsed, err = abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerImplementationMetaData.ABI))
	if err != nil {
		return fmt.Errorf("ontevm init abiParsed err:%v", err)
	}
	return
}

type MakeTxParamWithSender struct {
	Sender ontocommon.Address
	ccom.MakeTxParam
}

func (this *MakeTxParamWithSender) Serialization() (data []byte, err error) {
	sink := ontocommon.NewZeroCopySink(nil)
	sink.WriteAddress(this.Sender)
	this.MakeTxParam.Serialization(sink)
	data = sink.Bytes()
	return
}
func (this *MakeTxParamWithSender) Deserialization(data []byte) (err error) {
	source := ontocommon.NewZeroCopySource(data)
	addr, eof := source.NextAddress()
	if eof {
		err = fmt.Errorf("MakeTxParamWithSender NextAddress fail")
		return
	}
	this.Sender = ontocommon.Address(addr)
	return this.MakeTxParam.Deserialization(source)
}

type StorageLog struct {
	Address common.Address
	Topics  []common.Hash
	Data    []byte
}

func (self *StorageLog) Serialization(sink *ontocommon.ZeroCopySink) {
	sink.WriteAddress(ontocommon.Address(self.Address))
	sink.WriteUint32(uint32(len(self.Topics)))
	for _, t := range self.Topics {
		sink.WriteHash(ontocommon.Uint256(t))
	}
	sink.WriteVarBytes(self.Data)
}

func (self *StorageLog) Deserialization(source *ontocommon.ZeroCopySource) error {
	address, eof := source.NextAddress()
	if eof {
		return fmt.Errorf("StorageLog.address eof")
	}
	self.Address = common.Address(address)
	l, eof := source.NextUint32()
	if eof {
		return fmt.Errorf("StorageLog.l eof")
	}
	self.Topics = make([]common.Hash, 0, l)
	for i := uint32(0); i < l; i++ {
		h, _ := source.NextHash()
		if eof {
			return fmt.Errorf("StorageLog.h eof")
		}
		self.Topics = append(self.Topics, common.Hash(h))
	}

	data, err := source.ReadVarBytes()
	if err != nil {
		return err
	}

	self.Data = data
	return nil
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	events, err := l.sdk.Node().GetSmartContractEventByBlock(uint32(height))
	if err != nil {
		return nil, fmt.Errorf("ONTEVM failed to fetch smart contract events for height %d, err %v", height, err)
	}
	txs = []*msg.Tx{}
	eccmAddr := msg.HexStringReverse((l.ccm.String())[2:])
	for _, event0 := range events {
		for _, notify := range event0.Notify {
			if notify.ContractAddress == eccmAddr {
				states, ok := notify.States.(string)
				if !ok {
					continue
				}
				var data []byte
				data, err = hexutil.Decode(states)
				if err != nil {
					err = fmt.Errorf("decoding states err:%v", err)
					return nil, err
				}
				source := ontocommon.NewZeroCopySource(data)
				var storageLog StorageLog
				err = storageLog.Deserialization(source)
				if err != nil {
					return nil, err
				}

				if len(storageLog.Topics) == 0 || l.abiParsed.Events["CrossChainEvent"].ID != storageLog.Topics[0] {
					continue
				}

				var event eccm_abi.EthCrossChainManagerImplementationCrossChainEvent
				err = l.abiParsed.UnpackIntoInterface(&event, "CrossChainEvent", storageLog.Data)
				if err != nil {
					return nil, fmt.Errorf("ontevm unpack err %v", err)
				}
				tx := &msg.Tx{
					TxId:           msg.EncodeTxId(event.TxId),
					TxType:         msg.SRC,
					SrcHeight:      height,
					SrcChainId:     base.ONTEVM,
					SrcHash:        msg.HexStringReverse(event0.TxHash),
					DstChainId:     event.ToChainId,
					SrcParam:       hex.EncodeToString(event.Rawdata),
					SrcProofHeight: height,
					SrcEvent:       event.Rawdata,
				}
				txs = append(txs, tx)
			}
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
	h, err := l.sdk.Node().GetBlockHeightByTxHash(hash)
	txs, err := l.Scan(uint64(h))
	if err != nil {
		return
	}
	for _, tx := range txs {
		if tx.SrcHash == hash {
			return tx, nil
		}
	}
	return
}

func (l *Listener) Nodes() chains.Nodes {
	return l.sdk.ChainSDK
}

func (l *Listener) LatestHeight() (uint64, error) {
	return l.sdk.Node().GetLatestHeight()
}
