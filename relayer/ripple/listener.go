package ripple

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/ripple"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/rubblelabs/ripple/data"
	"math/big"
	"time"
)

type Listener struct {
	sdk              *ripple.SDK
	MultiSignAccount string
	config           *config.ListenerConfig
	name             string
}

type CrossChainInfo struct {
	DstChain   uint64
	DstAddress string
}

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.MultiSignAccount = config.MultiSignAccount
	l.sdk, err = ripple.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	ledger, err := l.sdk.Node().GetRpcClient().GetLedger(uint32(height))
	if err != nil {
		return nil, err
	}

	if ledger == nil {
		return nil, fmt.Errorf("get Ripple ledger failed, height=%d", height)
	}

	for _, txData := range ledger.Ledger.Transactions {
		if !txData.MetaData.TransactionResult.Success() {
			continue
		}
		payment, ok := txData.Transaction.(*data.Payment)
		if !ok {
			continue
		}
		if payment.Amount.Currency.Machine() != "XRP" || payment.Destination.String() != l.MultiSignAccount {
			continue
		}

		if len(payment.Memos) != 1 {
			log.Error("Ripple payment.Memos invalid", "txHash: %s", txData.GetHash().String())
			continue
		}

		log.Info("Found Ripple tx", "height", height, "hash", txData.GetHash().String(), "tx", fmt.Sprintf("%+v", *txData))

		crossChainInfo := new(CrossChainInfo)
		err = json.Unmarshal(payment.Memos[0].Memo.MemoData.Bytes(), crossChainInfo)
		if err != nil {
			log.Error("Ripple deserialize cross chain info failed",
				"hash", txData.GetHash().String(),
				"MemoData", string(payment.Memos[0].Memo.MemoData.Bytes()), "err", err)
			continue
		}

		dstAddress, err := hex.DecodeString(crossChainInfo.DstAddress)
		if err != nil {
			log.Error("Ripple deserialize dstAddress failed",
				"hash", txData.GetHash().String(),
				"crossChainInfo", fmt.Sprintf("%+v", *crossChainInfo), "err", err)
			continue
		}

		deliveredAmount, err := txData.MetaData.DeliveredAmount.NonNative()
		if err != nil {
			log.Error("Ripple txData.MetaData.DeliveredAmount.NonNative() failed", "hash", txData.GetHash().String(), "err", err)
			continue
		}
		amount, ok := new(big.Int).SetString(deliveredAmount.String(), 10)
		if !ok {
			log.Error("Ripple convert amount to big int  failed", "hash", txData.GetHash().String(), "amount", deliveredAmount)
			continue
		}
		rippleTxArgs := &common.RippleTxArgs{ToAddress: dstAddress, Amount: amount}
		b, err := rlp.EncodeToBytes(rippleTxArgs)
		if err != nil {
			log.Error("Ripple rlp.EncodeToBytes rippleTxArgs failed", "hash", txData.GetHash().String(), "err", err)
			continue
		}

		param := &common.MakeTxParam{
			TxHash:              txData.GetHash().Bytes(),
			CrossChainID:        txData.GetHash().Bytes(),
			FromContractAddress: payment.Destination[:],
			ToChainID:           crossChainInfo.DstChain,
			Method:              "unlock",
			Args:                b,
		}

		rawParam, err := rlp.EncodeToBytes(param)
		if err != nil {
			log.Error("Ripple rlp encode param failed", "hash", txData.GetHash().String(), "err", err)
			continue
		}

		//rawParam, err := msg.EncodeTxParam(param)
		//if err != nil {
		//	log.Error("Ripple EncodeTxParam failed", "hash", txData.GetHash().String(), "err", err)
		//	continue
		//}

		log.Info("Found Ripple src cross chain tx", "hash", txData.GetHash().String())

		tx := &msg.Tx{
			TxType:     msg.SRC,
			TxId:       txData.GetHash().String(),
			SrcHash:    txData.GetHash().String(),
			DstChainId: crossChainInfo.DstChain,
			SrcParam:   hex.EncodeToString(rawParam),
			SrcChainId: l.config.ChainId,
			SrcHeight:  height,
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

func (l *Listener) ScanTx(hash string) (*msg.Tx, error) {
	txData, err := l.sdk.Node().GetRpcClient().GetTx(hash)
	if err != nil {
		return nil, fmt.Errorf("ripple get tx failed. hash: %s, err: %s", hash, err)
	}

	txs, err := l.Scan(uint64(txData.Ledger()))
	if err != nil {
		return nil, err
	}

	for _, tx := range txs {
		if txData.GetHash().String() == tx.SrcHash {
			return tx, nil
		}
	}
	return nil, fmt.Errorf("%s is not Ripple src cross tx", hash)
}

func (l *Listener) GetTxBlock(hash string) (uint64, error) {
	tx, err := l.sdk.Node().GetRpcClient().GetTx(hash)
	if err != nil {
		return 0, fmt.Errorf("ripple get tx failed. hash: %s, err: %s", hash, err)
	}

	return uint64(tx.LedgerSequence), nil
}

func (l *Listener) Compose(tx *msg.Tx) error {
	return nil
}

func (l *Listener) LatestHeight() (uint64, error) {
	return l.sdk.Node().GetLatestHeight()
}

func (l *Listener) WaitTillHeight(ctx context.Context, height uint64, interval time.Duration) (uint64, bool) {
	return 0, false
}

func (l *Listener) GetFee() (float64, error) {
	return l.sdk.Node().GetFee()
}
