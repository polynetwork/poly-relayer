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
	"errors"
	"fmt"
	"sync"
	"time"

	sdk "github.com/ontio/ontology-go-sdk"

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
	config  *config.SubmitterConfig
	sdk     *ont.SDK
	signer  *sdk.Account
	name    string
	compose msg.PolyComposer
}

func (s *Submitter) Init(config *config.SubmitterConfig) (err error) {
	s.config = config
	s.signer, err = wallet.NewOntSigner(config.Wallet)
	s.name = base.GetChainName(config.ChainId)
	s.sdk, err = ont.WithOptions(base.ONT, config.Nodes, time.Minute, 1)
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

func (s *Submitter) submit(tx *msg.Tx, compose msg.PolyComposer) error {
	// TODO: Check storage to see if already imported
	err := s.compose(tx)
	if err != nil {
		return err
	}
	if tx.Param == nil || tx.SrcChainId == 0 {
		return fmt.Errorf("%s submitter src tx %s param is missing or src chain id not specified", s.name, tx.SrcHash)
	}

	if !config.CONFIG.AllowMethod(tx.Param.Method) {
		log.Error("Invalid src tx method", "src_hash", tx.SrcHash, "chain", s.name, "method", tx.Param.Method)
		return nil
	}

	if tx.SrcStateRoot == nil {
		tx.SrcStateRoot = []byte{}
	}

	return nil
}

func (s *Submitter) ProcessTx(m *msg.Tx, composer msg.PolyComposer) (err error) {
	if m.Type() != msg.SRC {
		return fmt.Errorf("%s desired message is not poly tx %v", m.Type())
	}

	return s.submit(m, composer)
}

func (s *Submitter) Process(msg msg.Message, composer msg.PolyComposer) error {
	return nil
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}

func (s *Submitter) run(bus bus.TxBus, compose msg.PolyComposer) error {
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return nil
		default:
		}
		tx, err := bus.Pop(context.Background())
		if err != nil {
			log.Error("Bus pop error", "err", err)
			continue
		}
		if tx == nil {
			time.Sleep(time.Second)
			continue
		}
		log.Info("Processing src tx", "src_hash", tx.SrcHash, "src_chain", tx.SrcChainId, "dst_chain", tx.DstChainId)
		err = s.submit(tx, compose)
		if err != nil {
			log.Error("Process poly tx error", "chain", s.name, "err", err)
			tx.Attempts++
			bus.Push(context.Background(), tx)
			if errors.Is(err, msg.ERR_PROOF_UNAVAILABLE) {
				time.Sleep(time.Second)
			}
		} else {
			log.Info("Submitted src tx to poly", "src_hash", tx.SrcHash, "poly_hash", tx.PolyHash)
		}
	}
}

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, bus bus.TxBus, composer msg.PolyComposer) error {
	s.Context = ctx
	s.wg = wg
	log.Info("Starting submitter worker", "index", 0, "total", 1, "account", s.signer.Address, "chain", s.name)
	go s.run(bus, composer)
	return nil
}
