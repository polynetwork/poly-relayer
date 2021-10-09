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

package poly

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ontio/ontology-crypto/signature"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"
	sdk "github.com/polynetwork/poly-go-sdk"

	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Submitter struct {
	context.Context
	wg      *sync.WaitGroup
	config  *config.PolySubmitterConfig
	sdk     *poly.SDK
	signer  *sdk.Account
	name    string
	sync    *config.HeaderSyncConfig
	compose msg.PolyComposer
	state   bus.ChainStore // Header sync marking

	// Check last header commit
	lastCommit uint64
	lastCheck  uint64
}

func (s *Submitter) Init(config *config.PolySubmitterConfig) (err error) {
	s.config = config
	s.signer, err = wallet.NewPolySigner(config.Wallet)
	if err != nil {
		return
	}
	s.name = base.GetChainName(config.ChainId)
	s.sdk, err = poly.WithOptions(base.POLY, config.Nodes, time.Minute, 1)
	return
}

func (s *Submitter) SDK() *poly.SDK {
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

func (s *Submitter) SubmitHeadersWithLoop(chainId uint64, headers [][]byte, header *msg.Header) (err error) {
	start := time.Now()
	h := uint64(0)
	if len(headers) > 0 {
		err = s.submitHeadersWithLoop(chainId, headers, header)
		if err == nil && header != nil {
			// Check last commit every 4 successful submit
			if s.lastCommit > 0 && s.lastCheck > 3 {
				s.lastCheck = 0
				switch chainId {
				case base.ONT, base.NEO, base.HEIMDALL, base.OK:
				default:
					height, e := s.GetSideChainHeight(chainId)
					if e == nil && height < s.lastCommit {
						err = msg.ERR_HEADER_MISSING
					}
				}
			} else {
				s.lastCheck++
			}
		}
	}
	if header != nil {
		h = header.Height
		if err == nil {
			s.state.HeightMark(h)        // Mark header sync height
			s.lastCommit = header.Height // Mark last commit
		}
	}
	log.Info("Submit headers to poly", "chain", chainId, "size", len(headers), "height", h, "elapse", time.Since(start), "err", err)
	return
}

func (s *Submitter) submitHeadersWithLoop(chainId uint64, headers [][]byte, header *msg.Header) error {
	var ok bool
	for {
		var err error
		if header != nil {
			ok, err = s.CheckHeaderExistence(header)
			if ok {
				return nil
			}
			if err != nil {
				log.Error("Failed to check header existence", "chain", chainId, "height", header.Height)
			}
		}

		if err == nil {
			_, err = s.SubmitHeaders(chainId, headers)
			if err == nil {
				return nil
			}
			info := err.Error()
			switch chainId {
			case base.OK:
				if strings.Contains(info, "no header you commited is useful") {
					log.Warn("Sync ok chain header to poly not commited", "reason", info)
					return nil
				}
			}
			if strings.Contains(info, "parent header not exist") || strings.Contains(info, "missing required field") || strings.Contains(info, "parent block failed") {
				//NOTE: reset header height back here
				log.Error("Possible hard fork, will rollback some blocks", "chain", chainId, "err", err)
				return msg.ERR_HEADER_INCONSISTENT
			}
			log.Error("Failed to submit header to poly", "chain", chainId, "err", err)
		}
		select {
		case <-s.Done():
			log.Warn("Header submitter exiting with headers not submitted", "chain", chainId)
			return nil
		default:
			time.Sleep(time.Second)
		}
	}
}

func (s *Submitter) SubmitHeaders(chainId uint64, headers [][]byte) (hash string, err error) {
	tx, err := s.sdk.Node().Native.Hs.SyncBlockHeader(
		chainId, s.signer.Address, headers, s.signer,
	)
	if err != nil {
		return "", err
	}
	hash = tx.ToHexString()
	_, err = s.sdk.Node().Confirm(hash, 0, 10)
	if err == nil {
		log.Info("Submitted header to poly", "chain", chainId, "hash", hash)
	}
	return
}

func (s *Submitter) submit(tx *msg.Tx) error {
	err := s.compose(tx)
	if err != nil {
		if strings.Contains(err.Error(), "missing trie node") {
			return msg.ERR_PROOF_UNAVAILABLE
		}
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

	var account []byte
	account = s.signer.Address[:]
	switch tx.SrcChainId {
	case base.NEO, base.ONT:
		if len(tx.SrcStateRoot) == 0 || len(tx.SrcProof) == 0 {
			return fmt.Errorf("%s submitter src tx src state root(%x) or src proof(%x) missing for chain %s with tx %s", s.name, tx.SrcStateRoot, tx.SrcProof, tx.SrcChainId, tx.SrcHash)
		}
	default:
		if tx.SrcChainId != base.OK {
			// For other chains, reversed?
			account = common.Hex2Bytes(s.signer.Address.ToHexString())
		}

		// Check done tx existence
		data, _ := s.sdk.Node().GetDoneTx(tx.SrcChainId, tx.Param.CrossChainID)
		if len(data) != 0 {
			log.Error("Tx already imported", "src_hash", tx.SrcHash)
			return nil
		}
	}

	t, err := s.sdk.Node().Native.Ccm.ImportOuterTransfer(
		tx.SrcChainId,
		tx.SrcEvent,
		uint32(tx.SrcProofHeight),
		tx.SrcProof,
		account,
		tx.SrcStateRoot,
		s.signer,
	)
	if err != nil {
		return fmt.Errorf("Failed to import tx to poly, %v tx %s", err, util.Json(tx))
	}
	tx.PolyHash = t.ToHexString()
	return nil
}

func (s *Submitter) ProcessTx(m *msg.Tx, _ msg.PolyComposer) (err error) {
	if m.Type() != msg.SRC {
		return fmt.Errorf("%s desired message is not poly tx %v", m.Type())
	}

	return s.submit(m)
}

func (s *Submitter) Process(msg msg.Message) error {
	return nil
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}

func (s *Submitter) CollectSigs(tx *msg.Tx) (err error) {
	var (
		sigs []byte
	)
	sigHeader := tx.PolyHeader
	if tx.AnchorHeader != nil && tx.AnchorProof != "" {
		sigHeader = tx.AnchorHeader
	}
	for _, sig := range sigHeader.SigData {
		temp := make([]byte, len(sig))
		copy(temp, sig)
		s, err := signature.ConvertToEthCompatible(temp)
		if err != nil {
			return fmt.Errorf("MakeTx signature.ConvertToEthCompatible %v", err)
		}
		sigs = append(sigs, s...)
	}
	tx.PolySigs = sigs
	return
}

func (s *Submitter) run(mq bus.TxBus) error {
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
		log.Info("Processing src tx", "src_hash", tx.SrcHash, "src_chain", tx.SrcChainId, "dst_chain", tx.DstChainId)
		err = s.submit(tx)
		if err != nil {
			log.Error("Submit src tx to poly error", "chain", s.name, "err", err)
			tx.Attempts++
			if errors.Is(err, msg.ERR_PROOF_UNAVAILABLE) {
				time.Sleep(2 * time.Second)
			}
			bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx) })
		} else {
			log.Info("Submitted src tx to poly", "src_hash", tx.SrcHash, "poly_hash", tx.PolyHash)
		}
	}
}

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, bus bus.TxBus, composer msg.PolyComposer) error {
	s.compose = composer
	s.Context = ctx
	s.wg = wg
	if s.config.Procs == 0 {
		s.config.Procs = 1
	}
	for i := 0; i < s.config.Procs; i++ {
		log.Info("Starting poly submitter worker", "index", i, "procs", s.config.Procs, "chain", s.name, "topic", bus.Topic())
		go s.run(bus)
	}
	return nil
}

func (s *Submitter) StartSync(
	ctx context.Context, wg *sync.WaitGroup, config *config.HeaderSyncConfig,
	reset chan<- uint64, state bus.ChainStore,
) (ch chan msg.Header, err error) {
	s.Context = ctx
	s.wg = wg
	s.sync = config
	s.state = state

	if s.sync.Batch == 0 {
		s.sync.Batch = 1
	}
	if s.sync.Buffer == 0 {
		s.sync.Buffer = 2 * s.sync.Batch
	}
	if s.sync.Timeout == 0 {
		s.sync.Timeout = 1
	}

	if s.sync.ChainId == 0 {
		return nil, fmt.Errorf("Invalid header sync side chain id")
	}

	ch = make(chan msg.Header, s.sync.Buffer)
	go s.startSync(ch, reset)
	return
}

func (s *Submitter) GetSideChainHeight(chainId uint64) (height uint64, err error) {
	return s.sdk.Node().GetSideChainHeight(chainId)
}

func (s *Submitter) CheckHeaderExistence(header *msg.Header) (ok bool, err error) {
	var hash []byte
	switch s.sync.ChainId {
	case base.OK:
		return
	case base.NEO, base.ONT:
		hash, err = s.sdk.Node().GetSideChainHeaderIndex(s.sync.ChainId, header.Height)
		if err != nil {
			return
		}
		ok = len(hash) != 0
		return
	default:
		hash, err = s.sdk.Node().GetSideChainHeader(s.sync.ChainId, header.Height)
		if err != nil {
			return
		}
		ok = bytes.Equal(hash, header.Hash)
	}
	return
}

func (s *Submitter) syncHeaderLoop(ch <-chan msg.Header, reset chan<- uint64) {
	for {
		select {
		case <-s.Done():
			return
		case header, ok := <-ch:
			if !ok {
				return
			}
			// NOTE err reponse here will revert header sync with delta - 2
			headers := [][]byte{header.Data}
			if header.Data == nil {
				headers = nil
			}
			err := s.SubmitHeadersWithLoop(s.sync.ChainId, headers, &header)
			if err != nil {
				reset <- header.Height - 2
			}
		}
	}
}

func (s *Submitter) syncHeaderBatchLoop(ch <-chan msg.Header, reset chan<- uint64) {
	headers := [][]byte{}
	commit := false
	duration := time.Duration(s.sync.Timeout) * time.Second
	var (
		height uint64
		hdr    *msg.Header
	)

COMMIT:
	for {
		select {
		case <-s.Done():
			break COMMIT
		case header, ok := <-ch:
			if ok {
				hdr = &header
				height = header.Height
				if hdr.Data == nil {
					// Update header sync height
					commit = true
				} else {
					headers = append(headers, header.Data)
					commit = len(headers) >= s.sync.Batch
				}
			} else {
				commit = len(headers) > 0
				break COMMIT
			}
		case <-time.After(duration):
			commit = len(headers) > 0
		}
		if commit {
			commit = false
			// NOTE err reponse here will revert header sync with delta -100
			err := s.SubmitHeadersWithLoop(s.sync.ChainId, headers, hdr)
			if err != nil {
				rollback := 1
				reset <- height - uint64(len(headers)+rollback)
			}
			headers = [][]byte{}
		}
	}
	if len(headers) > 0 {
		s.SubmitHeadersWithLoop(s.sync.ChainId, headers, hdr)
	}
}

func (s *Submitter) startSync(ch <-chan msg.Header, reset chan<- uint64) {
	if s.sync.Batch == 1 {
		s.syncHeaderLoop(ch, reset)
	} else {
		s.syncHeaderBatchLoop(ch, reset)
	}
	log.Info("Header sync exiting loop now")
}

func (s *Submitter) Poly() *poly.SDK {
	return s.sdk
}
