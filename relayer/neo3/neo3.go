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
	"fmt"
	"github.com/polynetwork/poly-relayer/store"
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
	VERIFY_SIG_AND_EXECUTE_TX     = "verifySigAndExecuteTx"
	VERIFY_AND_EXECUTE_TX_SUCCESS = "VerifyAndExecuteTxSuccess"
)

type Submitter struct {
	context.Context
	wg      *sync.WaitGroup
	config  *config.SubmitterConfig
	name    string
	sdk     *neo3.SDK
	neoCcmc string
	wallet  *wallet.Neo3Wallet // sign ToMerkleValue
	signer  *wallet.Neo3Wallet // sign neo tx
	polyId  uint64
	height  uint64
	store   *store.Store
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

	if config.Signer == nil {
		return fmt.Errorf("no neo3 wallet config file")
	}
	s.signer, err = wallet.NewNeo3Wallet(config.Signer, sdk)
	if err != nil {
		return fmt.Errorf("NewNeo3Wallet error: %v", err)
	}

	s.polyId = zion.ReadChainID()
	s.store, err = store.NewStore(s.polyId)
	if err != nil {
		return fmt.Errorf("store.NewStore error: %v", err)
	}
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
		go s.run(a, delay, composer, s.store) //
	}
	// scan zion
	go s.start(bus)
	return nil
}

func (s *Submitter) start(mq bus.TxBus) {
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
			time.Sleep(time.Second * 5)
			continue
		}
		// add tx to db
		t, err := s.convertTx(tx)
		if err != nil {
			log.Error("submitter convertTx error", "err", err)
			continue
		}
		if t == nil {
			time.Sleep(time.Second * 5)
			continue
		}
		var list []*store.Tx
		list = append(list, t)
		err = s.store.InsertTxs(list)
		if err != nil {
			log.Error("Fetch poly tx failure", "poly hash", tx.PolyHash.String(), "err", err)
			continue
		}
		time.Sleep(time.Second * 5)
	}
}

func (s *Submitter) convertTx(tx *msg.Tx) (*store.Tx, error) {
	var ethTmv *common.ToMerkleValue
	if tx.MerkleValue != nil {
		ethTmv = tx.MerkleValue
	} else {
		if len(tx.PolyParam) != 0 {
			value, err := hex.DecodeString(tx.PolyParam)
			if err != nil {
				return nil, fmt.Errorf("decode tx.PolyParam error: %v", err)
			}
			err = rlp.DecodeBytes(value, ethTmv)
		} else {
			return nil, fmt.Errorf("no ToMerkleValue info provided")
		}
	}
	neoTmv := convertEthTmvToNeoTmv(ethTmv)
	if neoTmv.TxParam.ToChainID != s.config.ChainId {
		return nil, nil
	}
	rawNeoTmv, err := SerializeMerkleValue(neoTmv)
	if err != nil {
		return nil, fmt.Errorf("neo3 SerializeMerkleValue error: %v", err)
	}
	t := &store.Tx{Hash: tx.PolyHash, Value: rawNeoTmv, Height: tx.PolyHeight, ChainID: s.polyId}
	k, err := tx.GetTxId()
	if err != nil {
		return nil, fmt.Errorf("tx.GetTxId error: %v, PolyHash: %s", err, tx.PolyHash.String())
	}
	t.TxID = k[:]
	return t, nil
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

	m.DstPolyEpochStartHeight = 1 // neo3 does not need to sync zion header
	err = compose(m)
	if err != nil {
		return
	}
	return s.processPolyTx(m)
}

func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	rawNeoTmv, err := hex.DecodeString(tx.PolyParam)
	if err != nil {
		return fmt.Errorf("decode PolyParam error: %v", err)
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

func (s *Submitter) GetPolyEpochStartHeight() (uint64, error) {
	return 1, nil // neo3 doesn't need to sync zion headers
}

func (s *Submitter) SubmitTx(tx *msg.Tx) (err error) {
	if tx.CheckFeeStatus == bridge.PAID_LIMIT && !tx.CheckFeeOff {
		return fmt.Errorf("%s does not support fee paid with max limit", s.name)
	}
	tx.DstHash, err = s.signer.SendTransaction(tx.DstData) // signer is used to send tx
	return
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}

func (s *Submitter) run(account nw.NEP6Account, delay bus.DelayedTxBus, compose msg.PolyComposer, store *store.Store) {
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return
		default:
		}

		txs, err := store.LoadTxs(1)
		if err != nil {
			log.Error("Failed to load txs from store", "err", err)
			continue
		}
		if len(txs) == 0 {
			time.Sleep(time.Second * 5)
			continue
		}

		storeTx := txs[0]
		tx := new(msg.Tx)
		tx.TxType = msg.POLY
		tx.PolyHash = storeTx.Hash
		tx.PolyParam = hex.EncodeToString(storeTx.Value)
		tx.DstSender = &account

		log.Info("Processing poly tx", "poly_hash", tx.PolyHash.Hex(), "tmv signer", account.Address)

		err = s.ProcessTx(tx, compose)
		if err == nil {
			err = s.SubmitTx(tx)
		}

		if err != nil {
			log.Error("Process poly tx error", "poly_hash", tx.PolyHash.String(), "err", err)
			log.Json(log.ERROR, tx)
		} else {
			done, err := s.checkDone(tx.DstHash)
			if err != nil {
				log.Error("checkDone error", "dst_hash", tx.DstHash, "err", err)
			}
			if !done {
				log.Info("Collecting sigs for poly tx", "poly_hash", tx.PolyHash.String(), "dst_hash", tx.DstHash)
			} else {
				log.Info("Submitted poly tx", "poly_hash", tx.PolyHash.String(), "dst_hash", tx.DstHash)
			}
			// delete from db
			err = store.DeleteTxs(storeTx)
			if err != nil {
				log.Error("store.DeleteTxs error", "poly_hash", tx.PolyHash.String(), "err", err)
			}
		}

		time.Sleep(time.Second * 5)
	}
}

func (s *Submitter) checkDone(hash string) (bool, error) {
	res := s.sdk.Node().GetApplicationLog(hash)
	if res.HasError() {
		return false, fmt.Errorf(res.GetErrorInfo())
	}
	for _, execution := range res.Result.Executions {
		if execution.VMState == "FAULT" {
			return false, fmt.Errorf("engine falted: %s", execution.Exception)
		}
		for _, notification := range execution.Notifications {
			u, _ := helper.UInt160FromString(notification.Contract)
			if "0x"+u.String() == s.neoCcmc && notification.EventName == VERIFY_AND_EXECUTE_TX_SUCCESS {
				return true, nil
			}
		}
	}

	return false, nil // signature not enough
}
