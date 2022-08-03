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

package zion

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/devfans/zion-sdk/contracts/native/utils"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/rlp"

	ccom "github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"
	"github.com/devfans/zion-sdk/contracts/native/info_sync"

	ccm "github.com/devfans/zion-sdk/contracts/native/go_abi/cross_chain_manager_abi"
	hs "github.com/devfans/zion-sdk/contracts/native/go_abi/info_sync_abi"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/eth"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/wallet"

	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/store"
)

type Submitter struct {
	context.Context
	wg       *sync.WaitGroup
	config   *config.SubmitterConfig
	sdk      *zion.SDK
	name     string
	sync     *config.HeaderSyncConfig
	vote     *config.TxVoteConfig
	composer msg.SrcComposer
	wallet   wallet.IWallet
	voter    wallet.IWallet
	signer   *accounts.Account

	// Check last header commit
	lastCommit   uint64
	lastCheck    uint64
	blocksToWait uint64
	txabi        abi.ABI
	hsabi        abi.ABI
}

type Composer struct {
	compose msg.PolyComposer
}

func (c *Composer) LatestHeight() (uint64, error) { return 0, nil }
func (c *Composer) Compose(tx *msg.Tx) error      { return c.compose(tx) }

func (s *Submitter) Init(config *config.SubmitterConfig) (err error) {
	s.config = config
	s.name = base.GetChainName(config.ChainId)
	s.blocksToWait = base.BlocksToWait(config.ChainId)
	log.Info("Chain blocks to wait", "blocks", s.blocksToWait, "chain", s.name)
	s.sdk, err = zion.WithOptions(base.POLY, config.Nodes, time.Minute, 1)
	if err != nil {
		return
	}
	if config.Wallet != nil {
		sdk, err := eth.WithOptions(base.POLY, config.Wallet.Nodes, time.Minute, 1)
		if err != nil {
			return err
		}
		s.wallet = wallet.New(config.Wallet, sdk)
		err = s.wallet.Init()
		if err != nil {
			return err
		}
		accounts := s.wallet.Accounts()
		if len(accounts) > 0 {
			s.signer = &accounts[0]
		}
		if config.Signer != nil {
			s.voter = wallet.New(config.Signer, sdk)
			err = s.voter.Init()
			if err != nil {
				return err
			}
		}
	}
	s.hsabi, err = abi.JSON(strings.NewReader(hs.IInfoSyncABI))
	if err != nil {
		return
	}

	s.txabi, err = abi.JSON(strings.NewReader(ccm.ICrossChainManagerABI))
	return
}

func (s *Submitter) SDK() *zion.SDK {
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

	signer := s.signer
	if tx.PolySender != nil {
		signer = tx.PolySender.(*accounts.Account)
	}
	switch tx.SrcChainId {
	case base.NEO, base.ONT:
		if len(tx.SrcStateRoot) == 0 || len(tx.SrcProof) == 0 {
			return fmt.Errorf("%s submitter src tx src state root(%x) or src proof(%x) missing for chain %d with tx %s", s.name, tx.SrcStateRoot, tx.SrcProof, tx.SrcChainId, tx.SrcHash)
		}
	default:
		// For other chains, reversed?
		// Check done tx existence
		done, err := s.sdk.Node().CheckDone(nil, tx.SrcChainId, tx.Param.CrossChainID)
		if err != nil {
			return err
		}
		if done {
			log.Info("Tx already imported", "src_hash", tx.SrcHash)
			return nil
		}
	}
	data, err := s.txabi.Pack("importOuterTransfer",
		tx.SrcChainId, uint32(tx.SrcProofHeight),
		tx.SrcProof,
		signer.Address[:],
		tx.SrcEvent,
		tx.SrcStateRoot,
	)
	if err != nil {
		return fmt.Errorf("Pack zion tx failed err %v", err)
	}
	hash, err := s.wallet.SendWithAccount(*signer, zion.CCM_ADDRESS, big.NewInt(0), 0, nil, nil, data)
	/*
		t, err := s.sdk.Node().Native.Ccm.ImportOuterTransfer(
			tx.SrcChainId,
			tx.SrcEvent,
			uint32(tx.SrcProofHeight),
			tx.SrcProof,
			account,
			tx.SrcStateRoot,
			s.signer,
		)
	*/
	if err != nil {
		if strings.Contains(err.Error(), "tx already done") {
			log.Info("Tx already imported", "src_hash", tx.SrcHash, "chain", tx.SrcChainId)
			return nil
		} else if strings.Contains(err.Error(), "already known") {
			return msg.ERR_TX_PENDING
		}
		return fmt.Errorf("Failed to import tx to poly, %v tx src hash %s", err, tx.SrcHash)
	}
	tx.PolyHash = msg.Hash(hash)
	return nil
}

func (s *Submitter) ProcessTx(m *msg.Tx, composer msg.PolyComposer) (err error) {
	if m.Type() != msg.SRC {
		return fmt.Errorf("desired message is not poly tx %v", m.Type())
	}
	s.composer = &Composer{composer}
	return s.submit(m)
}

func (s *Submitter) Process(msg msg.Message, composer msg.PolyComposer) error {
	return nil
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}

func (s *Submitter) ReadyBlock() (height uint64) {
	var err error
	switch s.config.ChainId {
	case base.ETH, base.BSC, base.HECO, base.O3, base.MATIC, base.STARCOIN, base.BYTOM, base.HSC:
		var h uint32
		h, err = s.sdk.Node().GetInfoHeight(nil, s.config.ChainId)
		height = uint64(h)
	default:
		height, err = s.composer.LatestHeight()
	}
	if err != nil {
		log.Error("Failed to get ready block height", "chain", s.name, "err", err)
	}
	return
}

func (s *Submitter) RetryWithData(account accounts.Account, store *store.Store, batch int) {
	list, err := store.LoadData(batch)
	if err != nil {
		log.Error("Failed to load data list", "err", err)
	} else {
		now := time.Now().Unix()
		for _, tx := range list {
			if tx.Time > uint64(now-600) {
				continue
			}
			height, pending, err := s.sdk.Node().GetTxHeight(context.Background(), tx.Hash)
			if err != nil {
				log.Error("Failed to check tx receipt", "hash", tx.Hash, "err", err)
			} else if height > 0 {
				bus.SafeCall(s.Context, tx.Hash, "remove tx item failure", func() error {
					return store.DeleteData(tx)
				})
			} else if !pending {
				hash, err := s.wallet.SendWithAccount(account, tx.To, big.NewInt(0), 0, nil, nil, tx.Data)
				// TODO: detect already done tx here
				if err != nil || hash == "" {
					log.Error("Failed to send tx during check", "err", err, "hash", hash)
					continue
				}
				bus.SafeCall(s.Context, tx.Hash, "remove tx item failure", func() error {
					return store.DeleteData(tx)
				})
				log.Info("Send tx vote during check", "hash", hash, "chain", s.name)
				bus.SafeCall(s.Context, hash, "insert data item failure", func() error {
					return store.InsertData(msg.HexToHash(hash), tx.Data, tx.To)
				})
			}
		}
	}
}

func (s *Submitter) VoteHeaderOfHeight(height uint32, header []byte, store *store.Store) (err error) {
	info := &info_sync.RootInfo{
		Height: height,
		Info:   header,
	}
	headerData, err := rlp.EncodeToBytes(info)
	if err != nil {
		log.Error("Failed to rlp root info", "err", err)
		return
	}

	infos := [][]byte{headerData}
	param := info_sync.SyncRootInfoParam{
		ChainID:   s.sync.ChainId,
		RootInfos: infos,
	}
	digest, err := param.Digest()
	if err != nil {
		log.Error("Failed to get param digest", "err", err)
		return
	}
	param.Signature, err = s.voter.SignHash(digest)
	if err != nil {
		log.Error("Failed to sign param", "err", err)
		return
	}
	data, err := s.hsabi.Pack("syncRootInfo", s.sync.ChainId, infos, param.Signature)
	if err != nil {
		log.Error("Failed to pack data", "err", err)
		return
	}
	hash, err := s.wallet.Send(zion.INFO_SYNC_ADDRESS, big.NewInt(0), 0, nil, nil, data)
	if err != nil || hash == "" {
		log.Error("Failed to send header", "err", err, "hash", hash)
		return
	}
	log.Info("Send header vote", "src height", height, "zion hash", hash, "chain", s.name)
	bus.SafeCall(s.Context, hash, "insert data item failure", func() error {
		return store.InsertData(msg.HexToHash(hash), data, zion.CCM_ADDRESS)
	})
	return
}

func (s *Submitter) ReplenishHeaderSync(chainId uint64, heights []uint32) (hash common.Hash, err error) {
	method := "replenish"
	data, err := zion.SYNC_ABI.Pack(method, chainId, heights)
	if err != nil {
		return
	}
	hashStr, err := s.wallet.Send(utils.InfoSyncContractAddress, big.NewInt(0), 0, nil, nil, data)
	if err != nil {
		return
	}
	hash = common.HexToHash(hashStr)
	return
}

func (s *Submitter) voteHeader(account accounts.Account, store *store.Store) {
	s.wg.Add(1)
	defer s.wg.Done()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return
		default:
		}

		select {
		case <-ticker.C:
			s.RetryWithData(account, store, s.sync.Batch)
		default:
		}

		headers, err := store.LoadHeaders(s.sync.Batch)
		if err != nil {
			log.Error("Failed to load txs from store", "err", err)
			continue
		}
		if len(headers) == 0 {
			time.Sleep(time.Second)
			continue
		}

		infos := make([][]byte, len(headers))
		for i, header := range headers {
			info := &info_sync.RootInfo{
				Height: uint32(header.Height),
				Info:   header.Data,
			}
			data, err := rlp.EncodeToBytes(info)
			if err != nil {
				log.Fatal("Failed to rlp root info", "err", err)
			}
			infos[i] = data
		}
		param := info_sync.SyncRootInfoParam{
			ChainID:   s.sync.ChainId,
			RootInfos: infos,
		}
		digest, err := param.Digest()
		if err != nil {
			log.Error("Failed to get param digest", "err", err)
			continue
		}
		param.Signature, err = s.voter.SignHash(digest)
		if err != nil {
			log.Error("Failed to sign param", "err", err)
			continue
		}
		data, err := s.hsabi.Pack("syncRootInfo", s.sync.ChainId, infos, param.Signature)
		if err != nil {
			log.Error("Failed to pack data", "err", err)
			continue
		}

		hash, err := s.wallet.SendWithAccount(account, zion.INFO_SYNC_ADDRESS, big.NewInt(0), 0, nil, nil, data)
		if err != nil || hash == "" {
			info := err.Error()
			if strings.Contains(info, "signer already exist") {
				log.Warn("signer already exist, drop duplicate signature", "chain", s.sync.ChainId)
				bus.SafeCall(s.Context, hash, "remove tx item failure", func() error {
					return store.DeleteHeader(headers...)
				})
			} else {
				log.Error("Failed to send header", "err", err, "hash", hash)
			}
			continue
		}
		log.Info("Send header vote", "hash", hash, "chain", s.name)
		bus.SafeCall(s.Context, hash, "insert data item failure", func() error {
			return store.InsertData(msg.HexToHash(hash), data, zion.INFO_SYNC_ADDRESS)
		})
		bus.SafeCall(s.Context, hash, "remove tx item failure", func() error {
			return store.DeleteHeader(headers...)
		})
	}
}

func (s *Submitter) VoteTxOfHash(tx *msg.Tx, store *store.Store) (err error) {
	raw, err := hex.DecodeString(tx.SrcParam)
	if err != nil || len(raw) == 0 {
		log.Error("Unexpected empty raw data", "err", err, "hash", tx.SrcHash)
		return
	}

	param := ccom.EntranceParam{
		SourceChainID: tx.SrcChainId,
		Height:        uint32(tx.SrcHeight),
		Extra:         raw,
	}

	digest, err := param.Digest()
	if err != nil {
		log.Error("Failed to get param digest", "err", err)
		return
	}
	param.Signature, err = s.voter.SignHash(digest)
	if err != nil {
		log.Error("Failed to sign param", "err", err)
		return
	}
	data, err := s.txabi.Pack("importOuterTransfer", param.SourceChainID, param.Height, []byte{}, param.Extra, param.Signature)
	if err != nil {
		log.Error("Failed to pack data", "err", err)
		return
	}

	hash, err := s.wallet.Send(zion.CCM_ADDRESS, big.NewInt(0), 0, nil, nil, data)
	if err != nil || hash == "" {
		log.Error("Failed to send tx", "err", err, "hash", hash)
		return
	}
	log.Info("Send tx vote", "src height", tx.SrcHeight, "src hash", tx.SrcHash, "zion hash", hash, "chain", s.name)
	bus.SafeCall(s.Context, hash, "insert data item failure", func() error {
		return store.InsertData(msg.HexToHash(hash), data, zion.CCM_ADDRESS)
	})
	return
}

func (s *Submitter) ReplenishTxVote(chainId uint64, txHashes []string) (hash common.Hash, err error) {
	method := "replenish"
	data, err := zion.CCM_ABI.Pack(method, chainId, txHashes)
	if err != nil {
		return
	}
	hashStr, err := s.wallet.Send(utils.CrossChainManagerContractAddress, big.NewInt(0), 0, nil, nil, data)
	if err != nil {
		return
	}
	hash = common.HexToHash(hashStr)
	return
}

func (s *Submitter) voteTx(account accounts.Account, store *store.Store) {
	s.wg.Add(1)
	defer s.wg.Done()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return
		default:
		}

		select {
		case <-ticker.C:
			s.RetryWithData(account, store, s.vote.Batch)
		default:
		}

		txs, err := store.LoadTxs(s.vote.Batch)
		if err != nil {
			log.Error("Failed to load txs from store", "err", err)
			continue
		}
		for _, tx := range txs {
			param := ccom.EntranceParam{
				SourceChainID: tx.ChainID,
				Height:        uint32(tx.Height),
				Extra:         tx.Value,
			}
			digest, err := param.Digest()
			if err != nil {
				log.Error("Failed to get param digest", "err", err)
				continue
			}
			param.Signature, err = s.voter.SignHash(digest)
			if err != nil {
				log.Error("Failed to sign param", "err", err)
				continue
			}
			data, err := s.txabi.Pack("importOuterTransfer", tx.ChainID, tx.Height, []byte{}, tx.Value, param.Signature)
			if err != nil {
				log.Error("Failed to pack data", "err", err)
				continue
			}

			hash, err := s.wallet.SendWithAccount(account, zion.CCM_ADDRESS, big.NewInt(0), 0, nil, nil, data)
			if err != nil || hash == "" {
				log.Error("Failed to send tx", "err", err, "hash", hash)
				continue
			}
			log.Info("Send tx vote", "hash", hash, "chain", s.name)
			bus.SafeCall(s.Context, hash, "insert data item failure", func() error {
				return store.InsertData(msg.HexToHash(hash), data, zion.CCM_ADDRESS)
			})
			bus.SafeCall(s.Context, hash, "remove tx item failure", func() error {
				return store.DeleteTxs(tx)
			})
		}
	}
}

func (s *Submitter) consume(account accounts.Account, mq bus.SortedTxBus) error {
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
			tx.PolySender = &account
			log.Info("Processing src tx", "src_hash", tx.SrcHash, "src_chain", tx.SrcChainId, "dst_chain", tx.DstChainId)
			err = s.submit(tx)
			if err == nil {
				log.Info("Submitted src tx to poly", "src_hash", tx.SrcHash, "poly_hash", tx.PolyHash)
				continue
			}
			block += 1
			if err == msg.ERR_TX_PENDING {
				block += 69
			}
			tx.Attempts++
			log.Error("Submit src tx to poly error", "chain", s.name, "err", err, "proof_height", tx.SrcProofHeight, "next_try", block)
			bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx, block) })
		} else {
			bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx, block) })
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, bus bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer) error {
	return nil
}

func (s *Submitter) Run(ctx context.Context, wg *sync.WaitGroup, mq bus.SortedTxBus, composer msg.SrcComposer) error {
	s.composer = composer
	s.Context = ctx
	s.wg = wg

	accounts := s.wallet.Accounts()
	if len(accounts) == 0 {
		log.Warn("No account available for submitter workers", "chain", s.name)
	}
	for i, a := range accounts {
		log.Info("Starting zion submitter worker", "index", i, "total", len(accounts), "account", a.Address, "chain", s.name, "topic", mq.Topic())
		go s.consume(a, mq)
	}
	return nil
}

func (s *Submitter) StartHeaderVote(
	ctx context.Context, wg *sync.WaitGroup, config *config.HeaderSyncConfig, store *store.Store,
) {
	s.Context = ctx
	s.wg = wg
	s.sync = config

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
		log.Fatal("Invalid tx vote side chain id", "chain", s.sync.ChainId)
	}

	accounts := s.wallet.Accounts()
	if len(accounts) == 0 {
		log.Warn("No account available for submitter workers", "chain", s.name)
	}
	for i, a := range accounts {
		log.Info("Starting zion submitter worker", "index", i, "total", len(accounts), "account", a.Address, "chain", s.name)
		go s.voteHeader(a, store)
	}
	return
}

func (s *Submitter) StartTxVote(
	ctx context.Context, wg *sync.WaitGroup, config *config.TxVoteConfig, store *store.Store,
) {
	s.Context = ctx
	s.wg = wg
	s.vote = config

	if s.vote.Batch == 0 {
		s.vote.Batch = 1
	}
	if s.vote.Buffer == 0 {
		s.vote.Buffer = 2 * s.sync.Batch
	}
	if s.vote.Timeout == 0 {
		s.vote.Timeout = 1
	}

	if s.vote.ChainId == 0 {
		log.Fatal("Invalid tx vote side chain id", "chain", s.sync.ChainId)
	}

	if s.signer == nil || s.wallet == nil {
		log.Fatal("Missing voter signer or sender")
	}

	accounts := s.wallet.Accounts()
	if len(accounts) == 0 {
		log.Warn("No account available for submitter workers", "chain", s.name)
	}
	for i, a := range accounts {
		log.Info("Starting zion submitter worker", "index", i, "total", len(accounts), "account", a.Address, "chain", s.name)
		go s.voteTx(a, store)
	}
	return
}

func (s *Submitter) GetSideChainHeight(chainId uint64) (height uint64, err error) {
	h, err := s.sdk.Node().GetInfoHeight(nil, chainId)
	height = uint64(h)
	return
}

func (s *Submitter) Poly() *zion.SDK {
	return s.sdk
}

func (s *Submitter) ProcessEpochs(epochs []*msg.Tx) (err error) {
	panic("unexpected sync epoch to zion")
}
