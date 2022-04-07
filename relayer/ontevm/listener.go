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
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ontocommon "github.com/ontio/ontology/common"
	"github.com/ontio/ontology/merkle"
	ccom "github.com/ontio/ontology/smartcontract/service/native/cross_chain/common"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/ontevm"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	polycommon "github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	pcom "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"strings"
	"time"
)

type Listener struct {
	sdk       *ontevm.SDK
	poly      *poly.SDK
	ccm       string
	ccd       string
	config    *config.ListenerConfig
	name      string
	abiParsed abi.ABI
}

func (l *Listener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
	if config.ChainId != base.ONTEVM {
		return fmt.Errorf("ONTEVM chain id is incorrect in config %v", config.ChainId)
	}
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.ccm = common.HexToAddress(config.CCMContract).String()
	l.ccd = common.HexToAddress(config.CCDContract).String()
	l.poly = poly
	l.sdk, err = ontevm.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	if err != nil {
		return fmt.Errorf("ontevm.WithOptions err:%v", err)
	}
	l.abiParsed, err = abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return fmt.Errorf("ontevm init abiParsed err:%v", err)
	}
	return
}

func HexStringReverse(value string) string {
	aa, _ := hex.DecodeString(value)
	bb := HexReverse(aa)
	return hex.EncodeToString(bb)
}
func HexReverse(arr []byte) []byte {
	l := len(arr)
	x := make([]byte, 0)
	for i := l - 1; i >= 0; i-- {
		x = append(x, arr[i])
	}
	return x
}

func (l *Listener) getProofHeight(txHeight uint64) (height uint64, err error) {
	h, err := l.poly.Node().GetSideChainHeight(l.config.ChainId)
	if err != nil {
		return 0, fmt.Errorf("getProofHeight unsupported chain %s err %v", l.name, err)
	}
	if txHeight >= h {
		height = txHeight
	} else {
		height = h
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

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	if tx.SrcHeight == 0 {
		return fmt.Errorf("Invalid tx src height(0)")
	}
	v, err := l.poly.Node().GetSideChainMsg(base.ONTEVM, tx.SrcHeight)
	if err != nil {
		return fmt.Errorf("GetSideChainMsg:%s", err)
	}
	if len(v) == 0 {
		msg, err := l.sdk.Node().GetCrossChainMsg(uint32(tx.SrcHeight))
		if err != nil {
			return fmt.Errorf("err ontNode.GetCrossChainMsg:%s", err)
		}
		tx.SrcStateRoot, err = hex.DecodeString(msg)
		if err != nil {
			return fmt.Errorf("err tx.SrcStateRoot hex.DecodeString(msg):%s", err)
		}
	}
	hashes, err := l.sdk.Node().GetCrossStatesLeafHashes(float64(tx.SrcHeight))
	if err != nil {
		return fmt.Errorf("GetCrossStatesLeafHashes:%s", err)
	}
	param := ccom.MakeTxParam{}
	par, _ := hex.DecodeString(tx.SrcParam)
	err = param.Deserialization(ontocommon.NewZeroCopySource(par))
	if err != nil {
		return fmt.Errorf("err param.Deserialization::%s", err)
	}
	eccmAddr := HexStringReverse((l.ccm)[2:])
	ontEccmAddr, err := ontocommon.AddressFromHexString(eccmAddr)

	makeTxParamWithSender := &MakeTxParamWithSender{
		ontEccmAddr,
		param,
	}
	itemValue, err := makeTxParamWithSender.Serialization()
	if err != nil {
		return fmt.Errorf("err makeTxParamWithSender.Serialization:%s", err)
	}
	hashesx := make([]ontocommon.Uint256, 0)
	for _, v := range hashes.Hashes {
		uint256v, _ := ontocommon.Uint256FromHexString(v)
		hashesx = append(hashesx, uint256v)
	}
	path, err := merkle.MerkleLeafPath(itemValue, hashesx)
	if err != nil {
		return fmt.Errorf("err  merkle.MerkleLeafPath:%s", err)
	}
	tx.SrcProof = path
	tx.SrcProofHeight = tx.SrcHeight
	{
		value, _, _, _ := msg.ParseAuditPath(tx.SrcProof)
		if len(value) == 0 {
			return fmt.Errorf("ParseAuditPath got null param")
		}
		param := &ccom.MakeTxParam{}
		err = param.Deserialization(ontocommon.NewZeroCopySource(value))
		if err != nil {
			return fmt.Errorf("err param.Deserialization:%s", err)
		}
		tx.Param = &pcom.MakeTxParam{
			TxHash:              param.TxHash,
			CrossChainID:        param.CrossChainID,
			FromContractAddress: param.FromContractAddress,
			ToChainID:           param.ToChainID,
			ToContractAddress:   param.ToContractAddress,
			Method:              param.Method,
			Args:                param.Args,
		}
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
		return nil, nil, fmt.Errorf("ONTEVM unmarshal blockInfo error: %s", err)
	}
	if info.NewChainConfig != nil {
		return block.Header.ToArray(), nil, nil
	}
	return
}

type StorageLog struct {
	Address common.Address
	Topics  []common.Hash
	Data    []byte
}

func (self *StorageLog) Serialization(sink *polycommon.ZeroCopySink) {
	sink.WriteAddress(polycommon.Address(self.Address))
	sink.WriteUint32(uint32(len(self.Topics)))
	for _, t := range self.Topics {
		sink.WriteHash(polycommon.Uint256(t))
	}
	sink.WriteVarBytes(self.Data)
}

func (self *StorageLog) Deserialization(source *polycommon.ZeroCopySource) error {
	address, _ := source.NextAddress()
	self.Address = common.Address(address)
	l, _ := source.NextUint32()
	self.Topics = make([]common.Hash, 0, l)
	for i := uint32(0); i < l; i++ {
		h, _ := source.NextHash()
		self.Topics = append(self.Topics, common.Hash(h))
	}
	data, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("StorageLog.Data eof")
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
	eccmAddr := HexStringReverse((l.ccm)[2:])
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
				source := polycommon.NewZeroCopySource(data)
				var storageLog StorageLog
				err = storageLog.Deserialization(source)
				if err != nil {
					return nil, err
				}
				var event eccm_abi.EthCrossChainManagerCrossChainEvent
				err = l.abiParsed.UnpackIntoInterface(&event, "CrossChainEvent", storageLog.Data)
				if err != nil {
					return nil, err
				}
				tx := &msg.Tx{
					TxId:           msg.EncodeTxId(event.TxId),
					TxType:         msg.SRC,
					SrcHeight:      height,
					SrcChainId:     base.ONTEVM,
					SrcHash:        event0.TxHash,
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
	if l.poly == nil {
		err = fmt.Errorf("No poly sdk provided for ONTEVM FetchLastConsensus")
		return
	}
	if force != 0 {
		return force, nil
	}
	height, err = l.poly.Node().GetSideChainMsgHeight(base.ONTEVM)
	if err != nil {
		return
	}
	if height == 0 {
		height, err = l.poly.Node().GetSideChainHeight(base.ONTEVM)
	}
	if last > height {
		height = last
	}
	return
}
