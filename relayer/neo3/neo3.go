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

package neo3

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/sc"
	nw "github.com/joeqian10/neo3-gogogo/wallet"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/bridge"
	"github.com/polynetwork/bridge-common/chains/neo3"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/wallet"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

const (
	VERIFY_SIG_AND_EXECUTE_TX = "VerifySigAndExecuteTx"
)

type Submitter struct {
	context.Context
	wg      *sync.WaitGroup
	config  *config.SubmitterConfig
	name    string
	sdk     *neo3.SDK
	neoCcmc string
	wallet  *wallet.Neo3Wallet
	polyId  uint64
}

func (s *Submitter) Init(config *config.SubmitterConfig) (err error) {
	s.config = config
	s.name = base.GetChainName(config.ChainId)
	s.sdk, err = neo3.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	if err != nil {
		return
	}
	s.neoCcmc = config.CCMContract // big endian hex string prefixed with "0x"

	if config.Wallet == nil {
		return fmt.Errorf("no neo3 wallet config file")
	}
	sdk, err := neo3.WithOptions(config.ChainId, config.Wallet.Nodes, time.Minute, 1)
	if err != nil {
		return fmt.Errorf("neo3.WithOption error: %v", err)
	}
	s.wallet, err = wallet.NewNeo3Wallet(config.Wallet, sdk)
	if err != nil {
		return fmt.Errorf("NewNeo3Wallet error: %v", err)
	}

	s.polyId = zion.ReadChainID()
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

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, bus bus.TxBus, delay bus.DelayedTxBus, composer msg.PolyComposer) error {
	s.Context = ctx
	s.wg = wg
	accounts := s.wallet.Accounts
	if len(accounts) == 0 {
		log.Warn("No account available for submitter workers", "chain", s.name)
	}
	for i, a := range accounts {
		log.Info("Starting submitter worker", "index", i, "total", len(accounts), "account", a.Address, "chain", s.name)
		go s.run(a, bus, delay, composer)
	}
	return nil
}

func (s *Submitter) Process(m msg.Message, composer msg.PolyComposer) (err error) {
	tx, ok := m.(*msg.Tx)
	if !ok {
		return fmt.Errorf("%s Proccess: Invalid poly tx cast %v", s.name, m)
	}
	return s.ProcessTx(tx, composer)
}

func (s *Submitter) ProcessTx(m *msg.Tx, compose msg.PolyComposer) (err error) {
	if m.Type() != msg.POLY {
		return fmt.Errorf("desired message is not poly tx %v", m.Type())
	}
	// check chain id
	if m.DstChainId != s.config.ChainId {
		return fmt.Errorf("message dst chain does not match %v", m.DstChainId)
	}

	m.DstPolyEpochStartHeight = 1 // neo3 does not need to sync zion header
	err = compose(m)
	if err != nil {
		return
	}
	return s.processPolyTx(m)
}

func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	var ethTmv *common.ToMerkleValue
	if tx.MerkleValue != nil {
		ethTmv = tx.MerkleValue
	} else {
		if len(tx.PolyParam) != 0 {
			value, err := hex.DecodeString(tx.PolyParam)
			if err != nil {
				return fmt.Errorf("decode tx.PolyParam error: %v", err)
			}
			err = rlp.DecodeBytes(value, ethTmv)
		} else {
			return fmt.Errorf("no ToMerkleValue info provided")
		}
	}
	neoTmv := convertEthTmvToNeoTmv(ethTmv)
	rawNeoTmv, err := SerializeMerkleValue(neoTmv)
	if err != nil {
		return fmt.Errorf("neo3.SerializeMerkleValue error: %v", err)
	}
	// sign the ToMerkleValue, multi sig verification in neo3 ccmc
	var a *nw.NEP6Account
	if tx.DstSender == nil {
		a = s.wallet.Account()
	} else {
		a = tx.DstSender.(*nw.NEP6Account)
	}
	pair, err := a.GetKeyFromPassword(s.config.Wallet.Neo3Pwd)
	if err != nil {
		return fmt.Errorf("neo3.NEP6Account.GetKeyFromPassword error: %v", err)
	}
	sig, err := pair.Sign(rawNeoTmv)
	if err != nil {
		return fmt.Errorf("neo3.KeyPair.Sign error: %v", err)
	}
	// make ContractParameter
	crossInfo := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: rawNeoTmv,
	}
	sigInfo := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: sig,
	}
	pubKey := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: pair.PublicKey.EncodePoint(true), // 33 bytes
	}
	// build script
	scriptHash, err := helper.UInt160FromString(s.neoCcmc)
	if err != nil {
		return fmt.Errorf("neo3 ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, VERIFY_SIG_AND_EXECUTE_TX, []interface{}{crossInfo, sigInfo, pubKey})
	if err != nil {
		return fmt.Errorf("sc.MakeScript error: %s", err)
	}

	tx.DstData = script
	return
}

func (s *Submitter) ProcessEpochs(txs []*msg.Tx) (err error) {
	return // neo3 doesn't need to sync zion headers
}

func (s *Submitter) GetPolyEpochStartHeight(uint64) (uint64, error) {
	return 1, nil // neo3 doesn't need to sync zion headers
}

func (s *Submitter) SubmitTx(tx *msg.Tx) (err error) {
	if tx.CheckFeeStatus == bridge.PAID_LIMIT && !tx.CheckFeeOff {
		return fmt.Errorf("%s does not support fee paid with max limit", s.name)
	}
	if tx.DstSender == nil {
		tx.DstHash, err = s.wallet.SendTransaction(tx.DstData)
	} else {
		account := tx.DstSender.(*nw.NEP6Account)
		tx.DstHash, err = s.wallet.SendTransactionWithAccount(tx.DstData, account)
	}
	return
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}

func (s *Submitter) run(account nw.NEP6Account, mq bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer) {
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return
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
		log.Info("Processing poly tx", "poly_hash", tx.PolyHash, "account", account.Address)
		tx.DstSender = &account
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
			} else if errors.Is(err, msg.ERR_FEE_CHECK_FAILURE) {
				tsp := time.Now().Unix() + 10
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else {
				bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx) })
			}
		} else {
			log.Info("Submitted poly tx", "poly_hash", tx.PolyHash, "chain", s.name, "dst_hash", tx.DstHash)
		}
	}
}
