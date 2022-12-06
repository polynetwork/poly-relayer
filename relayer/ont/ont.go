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
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/devfans/zion-sdk/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ontio/ontology/common"
	"strings"
	"sync"
	"time"

	sdk "github.com/ontio/ontology-go-sdk"
	ccm "github.com/ontio/ontology/smartcontract/service/native/cross_chain/cross_chain_manager"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/ont"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/wallet"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Submitter struct {
	context.Context
	wg      *sync.WaitGroup
	ccm     common.Address
	config  *config.SubmitterConfig
	sdk     *ont.SDK
	signer  *wallet.OntSigner
	name    string
	compose msg.PolyComposer
}

func (s *Submitter) Init(config *config.SubmitterConfig) (err error) {
	s.config = config
	s.ccm, err = common.AddressFromHexString(s.config.CCMContract)
	if err != nil {
		return err
	}
	s.signer, err = wallet.NewOntSigner(config.Wallet)
	s.name = base.GetChainName(config.ChainId)
	s.sdk, err = ont.WithOptions(base.ONT, config.Nodes, time.Minute, 1)
	if err != nil {
		return
	}
	//s.polyId = poly.ReadChainID()
	return
}

func (s *Submitter) SDK() *ont.SDK {
	return s.sdk
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
		return fmt.Errorf("%s desired message is not poly tx %v", m.Type())
	}
	if m.DstChainId != s.config.ChainId {
		return fmt.Errorf("%s message dst chain does not match %v", m.DstChainId)
	}
	err = compose(m)
	if err != nil {
		return
	}
	return
	//return s.processPolyTx(m)
}

func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	//if tx.AuditPath == "" {
	//	return fmt.Errorf("Invalid poly audit path")
	//}
	//
	//param := &ccm.ProcessCrossChainTxParam{
	//	Address:     s.signer.Address,
	//	FromChainID: base.POLY,
	//	Height:      tx.PolyHeight + 1,
	//	Proof:       tx.AuditPath,
	//}
	//
	//v, _ := s.sdk.Node().GetSideChainHeaderIndex(s.polyId, uint64(tx.PolyHeight+1))
	//if len(v) == 0 {
	//	param.Header = tx.PolyHeader.ToArray()
	//}
	//
	//tx.Extra = param

	return
}

func (s *Submitter) SubmitTx(tx *msg.Tx) (err error) {
	cctx, err := hex.DecodeString(tx.PolyParam)
	if err != nil || len(cctx) == 0 {
		return fmt.Errorf("Poly param merke value missing or invalid")
	}

	hsHeader, err := rlp.EncodeToBytes(types.HotstuffFilteredHeader(tx.AnchorHeader))
	if err != nil {
		log.Error("EncodeToBytes Hotstuff failed", "polyHash", tx.PolyHash.Hex(), "err", err)
		return err
	}

	extra, err := types.ExtractHotstuffExtra(tx.AnchorHeader)
	if err != nil {
		log.Error("ExtractHotstuffExtra failed", "polyHash", tx.PolyHash.Hex(), "err", err)
		return
	}

	rawSeals, err := rlp.EncodeToBytes(extra.CommittedSeal)
	if err != nil {
		log.Error("rlp.EncodeToBytes failed", "polyHash", tx.PolyHash.Hex(), "err", err)
		return
	}

	hash, err := s.sdk.Node().WasmVM.InvokeWasmVMSmartContract(s.signer.Config.GasPrice, s.signer.Config.GasLimit,
		s.signer.Account, s.signer.Account, s.ccm, ccm.PROCESS_CROSS_CHAIN_TX,
		[]interface{}{hsHeader, rawSeals, tx.PolyAccountProof, tx.PolyStorageProof, cctx})
	if err == nil {
		tx.DstHash = hash.ToHexString()
	} else {
		info := err.Error()
		if strings.Contains(info, "tx already done") {
			log.Info("Ont tx already submitted", "poly_hash", tx.PolyHash, "msg", err.Error())
			return nil
		} else if strings.Contains(info, "state fault") {
			err = fmt.Errorf("%w ont tx submit error: %s", msg.ERR_TX_EXEC_FAILURE, info)
		}
	}
	return
}

func (s *Submitter) Process(msg msg.Message, composer msg.PolyComposer) error {
	return nil
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}

func (s *Submitter) run(account *sdk.Account, mq bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer) error {
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return nil
		default:
		}
		tx, err := mq.Pop(s.Context)
		if err != nil {
			log.Error("Bus pop error", "err", err)
			continue
		}
		if tx == nil {
			time.Sleep(time.Second)
			continue
		}
		log.Info("Processing poly tx", "poly_hash", tx.PolyHash, "account", account.Address.ToHexString())
		err = s.ProcessTx(tx, compose)
		if err == nil {
			err = s.SubmitTx(tx)
		}
		if err != nil {
			log.Error("Process poly tx error", "chain", s.name, "err", err)
			log.Json(log.ERROR, tx)
			if errors.Is(err, msg.ERR_INVALID_TX) || errors.Is(err, msg.ERR_TX_BYPASS) {
				log.Error("Skipped poly tx for error", "poly_hash", tx.PolyHash, "err", err)
				continue
			}
			tx.Attempts++
			if errors.Is(err, msg.ERR_TX_EXEC_FAILURE) {
				tsp := time.Now().Unix() + 60*3
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
				continue
			} else {
				bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx) })
			}
		} else {
			log.Info("Submitted poly tx", "poly_hash", tx.PolyHash, "chain", s.name, "dst_hash", tx.DstHash)
		}
	}
}

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, bus bus.TxBus, delay bus.DelayedTxBus, composer msg.PolyComposer) error {
	s.Context = ctx
	s.wg = wg
	log.Info("Starting submitter worker", "index", 0, "total", 1, "account", s.signer.Address.ToHexString(), "chain", s.name)
	go s.run(s.signer.Account, bus, delay, composer)
	return nil
}
