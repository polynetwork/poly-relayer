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
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ontio/ontology-crypto/signature"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/wallet"
	sdk "github.com/polynetwork/poly-go-sdk"

	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Submitter struct {
	context.Context
	wg       *sync.WaitGroup
	config   *config.PolySubmitterConfig
	sdk      *poly.SDK
	signer   *sdk.Account
	name     string
	sync     *config.HeaderSyncConfig
	composer msg.SrcComposer
	state    bus.ChainStore // Header sync marking

	// Check last header commit
	lastCommit   uint64
	lastCheck    uint64
	blocksToWait uint64
}

func (s *Submitter) Init(config *config.PolySubmitterConfig) (err error) {
	s.config = config
	if config.Wallet != nil && config.Wallet.Path != "" {
		s.signer, err = wallet.NewPolySigner(config.Wallet)
		if err != nil {
			return
		}
	} else {
		log.Warn("Skipping poly wallet init")
	}
	s.name = base.GetChainName(config.ChainId)
	s.blocksToWait = base.BlocksToWait(config.ChainId)
	log.Info("Chain blocks to wait", "blocks", s.blocksToWait, "chain", s.name)
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
				case base.ETH, base.HECO, base.BSC, base.MATIC, base.O3, base.PIXIE:
					height, e := s.GetSideChainHeight(chainId)
					if e != nil {
						log.Error("Get side chain header height failure", "err", e)
					} else if height < s.lastCommit {
						log.Error("Chain header submit confirm check failure", "chain", s.name, "height", height, "last_submit", s.lastCommit)
						err = msg.ERR_HEADER_MISSING
					} else {
						log.Info("Chain header submit confirm check success", "chain", s.name, "height", height, "last_submit", s.lastCommit)
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
	attempt := 0
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
			attempt += 1
			_, err = s.SubmitHeaders(chainId, headers)
			if err == nil {
				return nil
			}
			info := err.Error()
			if strings.Contains(info, "parent header not exist") ||
				strings.Contains(info, "missing required field") ||
				strings.Contains(info, "parent block failed") ||
				strings.Contains(info, "span not correct") ||
				strings.Contains(info, "VerifySpan err") {
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
			if attempt > 30 {
				log.Error("Header submit too many failed attempts", "chain", chainId, "attempts", attempt)
				return msg.ERR_HEADER_SUBMIT_FAILURE
			}
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
	err := s.composer.Compose(tx)
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
	switch tx.SrcChainId {
	case base.NEO, base.ONT:
		account = s.signer.Address[:]
		if len(tx.SrcStateRoot) == 0 || len(tx.SrcProof) == 0 {
			return fmt.Errorf("%s submitter src tx src state root(%x) or src proof(%x) missing for chain %s with tx %s", s.name, tx.SrcStateRoot, tx.SrcProof, tx.SrcChainId, tx.SrcHash)
		}
	default:
		// For other chains, reversed?
		account = common.Hex2Bytes(s.signer.Address.ToHexString())

		// Check done tx existence
		data, _ := s.sdk.Node().GetDoneTx(tx.SrcChainId, tx.Param.CrossChainID)
		if len(data) != 0 {
			log.Info("Tx already imported", "src_hash", tx.SrcHash)
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
		if strings.Contains(err.Error(), "tx already done") {
			log.Info("Tx already imported", "src_hash", tx.SrcHash, "chain", tx.SrcChainId)
			return nil
		}
		return fmt.Errorf("Failed to import tx to poly, %v tx src hash %s", err, tx.SrcHash)
	}
	tx.PolyHash = t.ToHexString()
	return nil
}

func (s *Submitter) ProcessTx(m *msg.Tx, composer msg.SrcComposer) (err error) {
	if m.Type() != msg.SRC {
		return fmt.Errorf("%s desired message is not poly tx %v", m.Type())
	}
	s.composer = composer
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

func (s *Submitter) ReadyBlock() (height uint64) {
	var err error
	switch s.config.ChainId {
	case base.ETH, base.BSC, base.HECO, base.O3, base.MATIC, base.PIXIE:
		height, err = s.sdk.Node().GetSideChainHeight(s.config.ChainId)
	default:
		height, err = s.composer.LatestHeight()
	}
	if height > s.blocksToWait {
		height -= s.blocksToWait
	}
	if err != nil {
		log.Error("Failed to get ready block height", "chain", s.name, "err", err)
	}
	return
}

func (s *Submitter) consume(mq bus.SortedTxBus) error {
	s.wg.Add(1)
	defer s.wg.Done()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	height := s.ReadyBlock()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return nil
		default:
		}

		select {
		case <-ticker.C:
			h := s.ReadyBlock()
			if h > 0 && height != h {
				height = h
				log.Info("Current ready block height", "chain", s.name, "height", height)
			}
		default:
		}

		tx, block, err := mq.Pop(s.Context)
		if err != nil {
			log.Error("Bus pop error", "err", err)
			continue
		}
		if tx == nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		if block <= height {
			log.Info("Processing src tx", "src_hash", tx.SrcHash, "src_chain", tx.SrcChainId, "dst_chain", tx.DstChainId)
			err = s.submit(tx)
			if err == nil {
				log.Info("Submitted src tx to poly", "src_hash", tx.SrcHash, "poly_hash", tx.PolyHash)
				continue
			}
			block += 1
			tx.Attempts++
			log.Error("Submit src tx to poly error", "chain", s.name, "err", err, "proof_height", tx.SrcProofHeight, "next_try", block)
			bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx, block) })
		} else {
			bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx, block) })
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (s *Submitter) run(mq bus.TxBus) error {
	s.wg.Add(1)
	defer s.wg.Done()
	ticker := time.NewTicker(800 * time.Millisecond)
	defer ticker.Stop()

	height := s.ReadyBlock()
	refresh := true

	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return nil
		default:
		}

		if refresh {
			select {
			case <-ticker.C:
				refresh = false
				height = s.ReadyBlock()
			default:
			}
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

		log.Debug("Poly submitter checking on src tx", "src_hash", tx.SrcHash, "src_chain", tx.SrcChainId)
		retry := true

		if height == 0 || tx.SrcHeight <= height {
			log.Info("Processing src tx", "src_hash", tx.SrcHash, "src_chain", tx.SrcChainId, "dst_chain", tx.DstChainId)
			err = s.submit(tx)
			if err != nil {
				log.Error("Submit src tx to poly error", "chain", s.name, "err", err, "proof_height", tx.SrcProofHeight)
				tx.Attempts++
			} else {
				log.Info("Submitted src tx to poly", "src_hash", tx.SrcHash, "poly_hash", tx.PolyHash)
				retry = false
			}
			if height == 0 {
				refresh = true
			}
		} else {
			refresh = true
		}

		if retry {
			bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx) })
		}
	}
}

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, mq bus.SortedTxBus, composer msg.SrcComposer) error {
	s.composer = composer
	s.Context = ctx
	s.wg = wg

	if s.config.Procs == 0 {
		s.config.Procs = 1
	}
	for i := 0; i < s.config.Procs; i++ {
		log.Info("Starting poly submitter worker", "index", i, "procs", s.config.Procs, "chain", s.name, "topic", mq.Topic())
		go s.consume(mq)
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
	if s.sync.ChainId == base.NEO || s.sync.ChainId == base.ONT {
		hash, err = s.sdk.Node().GetSideChainHeaderIndex(s.sync.ChainId, header.Height)
		if err != nil {
			return
		}
		ok = len(hash) != 0
		return
	}
	hash, err = s.sdk.Node().GetSideChainHeader(s.sync.ChainId, header.Height)
	if err != nil {
		return
	}
	ok = bytes.Equal(hash, header.Hash)
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
				reset <- height - uint64(len(headers)) - 2
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
