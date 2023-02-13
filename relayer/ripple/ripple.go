package ripple

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/ripple"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	rippleTypes "github.com/polynetwork/ripple-sdk/types"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Submitter struct {
	context.Context
	wg     *sync.WaitGroup
	config *config.SubmitterConfig
	sdk    *ripple.SDK
	//polySigner *poly_go_sdk.Account
	//polySdk    *poly.SDK
	name string
}

func (s *Submitter) ProcessEpochs(txes []*msg.Tx) error {
	return nil
}

func (s *Submitter) GetPolyEpochStartHeight() (height uint64, err error) {
	return 0, nil
}

func (s *Submitter) Init(config *config.SubmitterConfig) (err error) {
	s.config = config
	s.sdk, err = ripple.WithOptions(base.RIPPLE, config.Nodes, time.Minute, 1)
	if err != nil {
		return
	}
	//s.polySigner, err = wallet.NewPolySigner(polyConfig.Wallet)
	//if err != nil {
	//	err = fmt.Errorf("Init ripple Submitter, poly Wallet is nil,err: %v", err)
	//	return
	//}
	//s.polySdk, err = poly.WithOptions(base.POLY, polyConfig.Nodes, time.Minute, 1)
	s.name = base.GetChainName(config.ChainId)
	return
}

func (s *Submitter) Submit(msg msg.Message) error {
	return nil
}

func (s *Submitter) Hook(ctx context.Context, wg *sync.WaitGroup, ch <-chan msg.Message) error {
	s.Context = ctx
	s.wg = wg
	return nil
}

func (s *Submitter) ProcessTx(m *msg.Tx, compose msg.PolyComposer) (err error) {
	if m.Type() != msg.POLY {
		return fmt.Errorf("%s desired message is not poly tx %v", m.Type(), m.PolyHash)
	}
	if m.DstChainId != s.config.ChainId {
		return fmt.Errorf("%s message dst chain does not match %v", m.DstChainId, m.PolyHash)
	}
	err = compose(m)
	if err != nil {
		return
	}
	return s.processPolyTx(m)
}

func (s *Submitter) SubmitTx(tx *msg.Tx) (err error) {
	payment := new(rippleTypes.MultisignPayment)
	err = json.Unmarshal([]byte(tx.ChainTxJson), payment)
	if err != nil {
		err = fmt.Errorf("SubmitTx ripple Submitter, Unmarshal paymentn err: %v", err)
		return
	}
	submitMultisignRes, err := s.sdk.Select().GetRpcClient().SubmitMultisigned(payment)
	if err != nil {
		err = fmt.Errorf("SubmitTx ripple Submitter, SubmitMultisigned err: %v", err)
		return
	}

	log.Info("SubmitTx ripple submitMultisignRes", "Status", submitMultisignRes.Result.Status, "rippleHash", submitMultisignRes.Result.TxJson.Hash, "ErrorMessage", submitMultisignRes.Result.ErrorMessage, "EngineResultMessage", submitMultisignRes.Result.EngineResultMessage)
	if submitMultisignRes != nil {
		if strings.Contains(submitMultisignRes.Result.EngineResultMessage, "Fee insufficient") {
			err = fmt.Errorf("Fee insufficient")
			return
		}
	}
	tx.DstHash = submitMultisignRes.Result.TxJson.Hash
	return

}

func (s *Submitter) Process(m msg.Message, compose msg.PolyComposer) (err error) {
	tx, ok := m.(*msg.Tx)
	if !ok {
		return fmt.Errorf("%s Proccess: Invalid poly tx cast %v", s.name, m)
	}
	return s.ProcessTx(tx, compose)
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}

func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	return nil
}

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, txBus bus.TxBus, txBus2 bus.DelayedTxBus, composer msg.PolyComposer) error {
	return nil
}

func (s *Submitter) StartRipple(ctx context.Context, wg *sync.WaitGroup, bus bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer, sequence bus.Sequence) error {
	s.Context = ctx
	s.wg = wg

	go s.run(sequence)

	return nil
}

func (s *Submitter) run(sequenceCache bus.Sequence) error {
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return nil
		default:
		}

		nowSequence, err := sequenceCache.NowSequence(s.Context, s.config.ChainId)
		if err != nil || nowSequence == "" {
			log.Error("run NowSequence error", "chain", s.name, "err", err)
			acc, err := s.sdk.Select().GetRpcClient().GetAccountInfo(s.config.CCMContract)
			if err != nil {
				log.Error("run GetAccountInfo", "chain", s.name, "err", err)
				time.Sleep(time.Second)
				continue
			}
			sequence := *(acc.AccountData.Sequence)
			nowSequence = strconv.Itoa(int(sequence))
			if err = sequenceCache.SetSequence(s.Context, s.config.ChainId, nowSequence); err != nil {
				log.Error("run SetSequence error", "chain", s.name, "nowSequence", nowSequence, "err", err)
			}
		}
		log.Info("now tx sequence", "nowSequence", nowSequence, "chain", s.name)

		tx, err := sequenceCache.GetTx(s.Context, s.config.ChainId, nowSequence)
		if err != nil || tx == nil {
			if strings.Contains(err.Error(), "redis: nil") {
				log.Info("run GetTx info", "chain", s.name, "nowSequence", nowSequence)
			} else {
				log.Error("run GetTx err", "chain", s.name, "nowSequence", nowSequence, "err", err)
			}
			time.Sleep(time.Second * 3)
			continue
		}
		err = s.SubmitTx(tx)
		if err != nil {
			if errors.Is(err, msg.ERR_FEE_INSUFFICIENT) {
				log.Info("run need ReconstructRippleTx", "chain", s.name, "nowSequence", nowSequence)
				err = s.ReconstructRippleTx(tx)
				if err != nil {
					log.Error("run ReconstructRippleTx error", "chain", s.name, "nowSequence", nowSequence, "err", err)
				} else {
					log.Info("run ReconstructRippleTx end, ready DelTx", "chain", s.name, "nowSequence", nowSequence)
					err = sequenceCache.DelTx(s.Context, s.config.ChainId, nowSequence)
					if err != nil {
						log.Error("run ReconstructRippleTx end, DelTx error", "chain", s.name, "nowSequence", nowSequence, "err", err)
					}
				}
			}
		}
		acc, err := s.sdk.Select().GetRpcClient().GetAccountInfo(s.config.CCMContract)
		if err == nil && acc != nil {
			nextSequence := strconv.Itoa(int(*(acc.AccountData.Sequence)))
			err = sequenceCache.SetSequence(s.Context, s.config.ChainId, nextSequence)
			if err != nil {
				log.Error("run end SubmitTx SetSequence error", "chain", s.name, "nextSequence", nextSequence, "err", err)
			}
			if nextSequence > nowSequence {
				log.Info("run nextSequence grew, ready DelTx", "chain", s.name, "nowSequence", nowSequence, "nowSequence", nowSequence)
				err = sequenceCache.DelTx(s.Context, s.config.ChainId, nowSequence)
				if err != nil {
					log.Error("run end SubmitTx DelTx error", "chain", s.name, "del nowSequence", nowSequence, "err", err)
				}
			}
		}
	}
}

func (s *Submitter) ReconstructRippleTx(tx *msg.Tx) error {
	//txHash, err := hex.DecodeString(tx.TxId)
	//if err != nil {
	//	return err
	//}
	//_, err = s.polySdk.Select().Native.Ccm.ReconstructRippleTx(tx.DstChainId, tx.SrcChainId, txHash, s.polySigner)
	//return err

	return nil
}
