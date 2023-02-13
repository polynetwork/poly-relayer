package aptos

import (
	"context"
	"encoding/hex"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/aptos"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"strconv"
	"time"
)

type Listener struct {
	sdk                        *aptos.SDK
	ccm                        string
	CrossChainEventCreationNum string
	config                     *config.ListenerConfig
	name                       string
}

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.ccm = config.CCMContract
	l.CrossChainEventCreationNum = config.CrossChainEventCreationNum
	//l.poly = poly

	//l.state = bus.NewRedisChainStore(
	//	bus.ChainHeightKey{ChainId: config.ChainId, Type: bus.KEY_HEIGHT_HEADER}, bus.New(config.Bus.Redis),
	//	config.Bus.HeightUpdateInterval,
	//)

	l.sdk, err = aptos.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	return
}

func (l *Listener) Scan(sequence uint64) (txs []*msg.Tx, err error) {
	eventFilter := &aptos.EventFilter{Address: l.ccm, CreationNumber: l.CrossChainEventCreationNum, Query: make(map[string]interface{})}
	eventFilter.Query["limit"] = 10
	eventFilter.Query["start"] = sequence

	events, err := l.sdk.Node().GetEvents(eventFilter)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return
	}

	txs = []*msg.Tx{}
	for _, event := range events {
		srcTx, err := l.sdk.Node().GetTxByVersion(uint64(event.Version))
		if err != nil {
			log.Error("get transaction by version failed", "err", err)
			continue
		}

		rawData, ok := event.Data["raw_data"]
		if !ok {
			log.Error("no raw_data in aptos cross chain event", "sequenceNum", event.SequenceNumber)
			continue
		}
		rawDataBytes, err := hex.DecodeString(rawData.(string)[2:])
		if !ok {
			log.Error("hex.DecodeString aptos raw data failed", "sequenceNum", event.SequenceNumber, "err", err)
			continue
		}

		param, err := msg.DecodeTxParam(rawDataBytes)
		if err != nil {
			log.Error("msg.DecodeTxParam aptos raw data failed", "sequenceNum", event.SequenceNumber, "err", err)
			continue
		}
		log.Info("Found aptos src cross chain tx", "method", param.Method, "hash", srcTx.Hash, "sequence", event.SequenceNumber)

		toChainId, _ := strconv.ParseUint(event.Data["to_chain_id"].(string), 0, 32)

		tx := &msg.Tx{
			TxType:           msg.SRC,
			TxId:             event.Data["tx_id"].(string)[2:],
			SrcHash:          srcTx.Hash,
			DstChainId:       toChainId,
			SrcParam:         rawData.(string)[2:],
			SrcChainId:       l.config.ChainId,
			CCMEventSequence: uint64(event.SequenceNumber),
			SrcProxy:         l.ccm,
			DstProxy:         event.Data["to_contract"].(string),
			SrcAddress:       event.Data["sender"].(string),
		}
		txs = append(txs, tx)
	}
	return
}

func (l *Listener) Defer() int {
	return l.config.Defer
}

func (l *Listener) ListenCheck() time.Duration {
	return time.Second
}

func (l *Listener) ChainId() uint64 {
	return l.config.ChainId
}

func (l *Listener) Nodes() chains.Nodes {
	return l.sdk.ChainSDK
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	return nil, nil, nil
}

func (l *Listener) LastHeaderSync(u uint64, u2 uint64) (uint64, error) {
	return 0, nil
}

func (l *Listener) ScanTx(s string) (*msg.Tx, error) {
	return nil, nil // todo
}

func (l *Listener) GetTxBlock(s string) (uint64, error) {
	return 0, nil
}

func (l *Listener) Compose(tx *msg.Tx) error {
	return nil
}

func (l *Listener) LatestHeight() (uint64, error) {
	panic("implement me")
}

func (l *Listener) WaitTillHeight(ctx context.Context, height uint64, interval time.Duration) (uint64, bool) {
	return 0, false
}
