package starcoin

import (
	"context"
	"github.com/ontio/ontology/common/log"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/starcoin"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	starcoin_client "github.com/starcoinorg/starcoin-go/client"
	"strconv"
	"time"
)

type Listener struct {
	sdk                            *starcoin.SDK
	ccm                            string
	crossChainEventDataCreationNum string
	config                         *config.ListenerConfig
	name                           string
}

func (this *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	this.config = config
	this.name = base.GetChainName(config.ChainId)
	this.ccm = config.CCMContract
	this.crossChainEventDataCreationNum = config.CrossChainEventCreationNum
	this.sdk, err = starcoin.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	return
}

func (this *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	// TODO(Bob Ong) to replace address with crosschain event
	address := "0x416b32009fe49fcab1d5f2ba0153838f"
	typeTag := "0x416b32009fe49fcab1d5f2ba0153838f::CrossChainManager::crossChainEventData"
	eventFilter := starcoin_client.EventFilter{
		Address:   []string{address},
		TypeTags:  []string{typeTag},
		FromBlock: height,
		ToBlock:   &height,
	}

	events, err := this.sdk.Node().GetEvents(context.Background(), &eventFilter)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return
	}

	txs = []*msg.Tx{}
	for _, event := range events {
		eventData, err := HexToBytes(event.Data)
		if err != nil {
			log.Errorf("Scan |  hex.DecodeString error :%s", err.Error())
			return txs, err
		}
		crossChainEventData, err := BcsDeserializeCrossChainEvent(eventData)
		if err != nil {
			log.Errorf("fetchLockDepositEvents - BcsDeserializeCrossChainDepositEvent error :%s", err.Error())
			return txs, err
		}
		//var isTarget bool
		//if len(this.config.ProxyOrAssetContracts) > 0 {
		//	// // fmt.Println(tools.EncodeToHex(ccEvent.Sender))
		//	// fmt.Println("---------------- height -----------------")
		//	// fmt.Println(height)
		//	// fmt.Println("---------------- ProxyOrAssetContract -----------------")
		//	// fmt.Println(ccEvent.ProxyOrAssetContract)
		//	// fmt.Println(string(ccEvent.ProxyOrAssetContract)) //tools.EncodeToHex(ccEvent.ProxyOrAssetContract)
		//	// fmt.Println("---------------- TxId(crossChainEventData.TxId) -----------------")
		//	// fmt.Println(tools.EncodeToHex(ccEvent.TxId))
		//	// fmt.Println("---------------- ToChainId -----------------")
		//	// fmt.Println(ccEvent.ToChainId)
		//	// fmt.Println("---------------- ToContract -----------------")
		//	// fmt.Println(string(ccEvent.ToContract))
		//	// fmt.Println("---------------- RawData -----------------")
		//	// fmt.Println(tools.EncodeToHex(ccEvent.RawData))
		//	//var proxyOrAssetContract string
		//	proxyOrAssetContract := string(ccEvent.ProxyOrAssetContract) // for 'source' proxy contract, filter is outbound chain Id.
		//	for _, v := range this.config.ProxyOrAssetContracts {        // renamed TargetContracts
		//		chainIdArrMap, ok := v[proxyOrAssetContract]
		//		if ok {
		//			if len(chainIdArrMap["outbound"]) == 0 {
		//				isTarget = true
		//				break
		//			}
		//			for _, id := range chainIdArrMap["outbound"] {
		//				if id == ccEvent.ToChainId {
		//					isTarget = true
		//					break
		//				}
		//			}
		//			if isTarget {
		//				break
		//			}
		//		}
		//	}
		//	if !isTarget {
		//		continue
		//	}
		//}
		//param := &common2.MakeTxParam{}
		////_ = param.Deserialization(common.NewZeroCopySource([]byte(ccEvent.RawData)))
		//raw, _ := this.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
		//	append(append([]byte(cross_chain_manager.DONE_TX), autils.GetUint64Bytes(this.config.StarcoinConfig.SideChainId)...), param.CrossChainID...))
		//if len(raw) != 0 {
		//	log.Debugf("fetchLockDepositEvents - ccid %s (tx_hash: %s) already on poly",
		//		hex.EncodeToString(param.CrossChainID), evt.TransactionHash)
		//	continue
		//}
		//index := big.NewInt(0)
		//index.SetBytes(ccEvent.TxId)
		//txHash, err := tools.HexWithPrefixToBytes(evt.TransactionHash)
		//if err != nil {
		//	log.Errorf("fetchLockDepositEvents - tools.HexWithPrefixToBytes error: %s", err.Error())
		//	return false, err
		//}
		//// fmt.Println("---------------- Starcoin Transaction Hash -----------------")
		//// fmt.Println(tools.EncodeToHex(txHash))
		//crossTx := &CrossTransfer{
		//	txIndex: tools.EncodeBigInt(index), // tools.EncodeBigInt(ccEvent.TxId to big.Int),
		//	txId:    txHash,                    // starcoin tx hash
		//	toChain: uint32(ccEvent.ToChainId),
		//	value:   ccEvent.RawData,
		//	height:  height,
		//}
		//sink := common.NewZeroCopySink(nil)
		//crossTx.Serialization(sink)
		//err = this.db.PutStarcoinTxRetry(sink.Bytes(), evt)
		//if err != nil {
		//	log.Errorf("fetchLockDepositEvents - this.db.PutStarcoinTxRetry error: %s", err.Error())
		//	return false, err
		//}
		//log.Infof("fetchLockDepositEvent -  height: %d", height)
		ccmSequenceNum, err := strconv.ParseUint(event.EventSeqNumber, 0, 64)

		tx := &msg.Tx{
			TxType:           msg.SRC,
			TxId:             string(crossChainEventData.TxId)[2:],
			SrcHash:          event.TransactionHash,
			DstChainId:       crossChainEventData.ToChainId,
			SrcParam:         event.Data[2:],
			SrcChainId:       this.config.ChainId,
			CCMEventSequence: ccmSequenceNum,
			SrcProxy:         this.ccm,
			DstProxy:         starcoin_client.BytesToHexString(crossChainEventData.ToContract),
			SrcAddress:       starcoin_client.BytesToHexString(crossChainEventData.Sender),
		}
		txs = append(txs, tx)
	}
	return txs, nil

	//srcTx, err := this.sdk.Node().GetTxByVersion(uint64(event.Version))
	//if err != nil {
	//	log.Error("get transaction by version failed", "err", err)
	//	continue
	//}
	//
	//rawData, ok := event.Data["raw_data"]
	//if !ok {
	//	log.Error("no raw_data in aptos cross chain event", "sequenceNum", event.SequenceNumber)
	//	continue
	//}
	//rawDataBytes, err := hex.DecodeString(rawData.(string)[2:])
	//if !ok {
	//	log.Error("hex.DecodeString aptos raw data failed", "sequenceNum", event.SequenceNumber, "err", err)
	//	continue
	//}
	//
	//param, err := msg.DecodeTxParam(rawDataBytes)
	//if err != nil {
	//	log.Error("msg.DecodeTxParam aptos raw data failed", "sequenceNum", event.SequenceNumber, "err", err)
	//	continue
	//}
	//log.Info("Found aptos src cross chain tx", "method", param.Method, "hash", srcTx.Hash, "sequence", event.SequenceNumber)
	//
	//toChainId, _ := strconv.ParseUint(event.Data["to_chain_id"].(string), 0, 32)
	//
	//tx := &msg.Tx{
	//	TxType:           msg.SRC,
	//	TxId:             event.Data["tx_id"].(string)[2:],
	//	SrcHash:          srcTx.Hash,
	//	DstChainId:       toChainId,
	//	SrcParam:         rawData.(string)[2:],
	//	SrcChainId:       this.config.ChainId,
	//	CCMEventSequence: uint64(event.SequenceNumber),
	//	SrcProxy:         this.ccm,
	//	DstProxy:         event.Data["to_contract"].(string),
	//	SrcAddress:       event.Data["sender"].(string),
	//}
	//txs = append(txs, tx)
	// }
	// return
}

func (this *Listener) Defer() int {
	return this.config.Defer
}

func (this *Listener) ListenCheck() time.Duration {
	return time.Second
}

func (this *Listener) ChainId() uint64 {
	return this.config.ChainId
}

func (this *Listener) Nodes() chains.Nodes {
	return this.sdk.ChainSDK
}

func (this *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	return nil, nil, nil
}

func (this *Listener) LastHeaderSync(u uint64, u2 uint64) (uint64, error) {
	return 0, nil
}

func (this *Listener) ScanTx(s string) (*msg.Tx, error) {
	return nil, nil // todo
}

func (this *Listener) GetTxBlock(s string) (uint64, error) {
	return 0, nil
}

func (this *Listener) Compose(tx *msg.Tx) error {
	return nil
}

func (this *Listener) LatestHeight() (uint64, error) {
	panic("implement me")
}

func (this *Listener) WaitTillHeight(ctx context.Context, height uint64, interval time.Duration) (uint64, bool) {
	return 0, false
}
