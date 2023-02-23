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
	"github.com/polynetwork/bridge-common/chains/bridge"
	"github.com/polynetwork/poly-relayer/store"
	"strings"

	"sync"
	"time"

	ethcomm "github.com/ethereum/go-ethereum/common"

	"github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/sc"
	"github.com/polynetwork/bridge-common/base"
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
	vote    *config.Neo3PolyTxVoteConfig
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
		return fmt.Errorf("no neo3 sender wallet config file")
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
		return fmt.Errorf("no neo3 signer wallet config file")
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

func (s *Submitter) StartPolyTxVote(
	ctx context.Context, wg *sync.WaitGroup, config *config.Neo3PolyTxVoteConfig, store *store.Store, bridge *bridge.SDK,
) {
	s.Context = ctx
	s.wg = wg
	s.vote = config

	if s.vote.Batch == 0 {
		s.vote.Batch = 1
	}
	if s.vote.Timeout == 0 {
		s.vote.Timeout = 1
	}

	if s.signer == nil || s.wallet == nil {
		log.Fatal("Neo3 poly tx voter missing signer or sender")
	}

	log.Info("Starting Neo3 poly tx vote worker", "account", s.wallet.Account(), "chain", s.name)
	go s.votePolyTx(store, bridge)

	return
}

func (s *Submitter) convertRawNeoTmv(tx *msg.Tx) (rawNeoTmv []byte, err error) {
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
		log.Warn("to chain is not Neo3", "to chain", neoTmv.TxParam.ToChainID, "poly hash", tx.PolyHash.Hex())
		return
	}
	rawNeoTmv, err = SerializeMerkleValue(neoTmv)
	if err != nil {
		return nil, fmt.Errorf("neo3 SerializeMerkleValue error: %v", err)
	}
	return
}

func (s *Submitter) constructDstData(rawNeoTmv []byte) (dstData []byte, err error) {
	// sign the ToMerkleValue, multi sig verification in neo3 ccmc
	pair, err := s.signer.Account().GetKeyFromPassword(s.config.Signer.Neo3Pwd)
	if err != nil {
		return nil, fmt.Errorf("neo3.NEP6Account.GetKeyFromPassword error: %v", err)
	}
	sig, err := pair.Sign(rawNeoTmv)
	if err != nil {
		return nil, fmt.Errorf("neo3.KeyPair.Sign error: %v", err)
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
		return nil, fmt.Errorf("neo3 ccmc conversion error: %s", err)
	}
	dstData, err = sc.MakeScript(scriptHash, VERIFY_SIG_AND_EXECUTE_TX, []interface{}{crossInfo, sigInfo, pubKey})
	if err != nil {
		return nil, fmt.Errorf("sc.MakeScript error: %s", err)
	}
	return
}

func (s *Submitter) RetryWithData(store *store.Store, batch int) {
	list, err := store.LoadData(batch)
	if err != nil {
		log.Error("Failed to load data list", "err", err)
	} else {
		now := time.Now().Unix()
		for _, tx := range list {
			if tx.Time > uint64(now-600) {
				continue
			}
			needRetry := true
			hash := tx.Hash

			success, err := s.checkSuccess(tx.Hash.Hex())
			if err != nil {
				log.Error("Failed to check tx status", "hash", tx.Hash.Hex(), "err", err)
			} else if success {
				log.Info("Confirm vote success", "hash", tx.Hash.Hex(), "err", err)
				needRetry = false
			} else {
				txHash, err := s.wallet.SendTransaction(tx.Data)
				if err != nil {
					log.Error("Failed to vote neo3 poly tx during check", "err", err, "hash", hash)
				} else {
					tx.Hash = msg.HexToHash(txHash)
					log.Info("Vote neo3 poly tx during check", "hash", txHash, "chain", s.name)
				}
			}

			// Delete old data
			bus.SafeCall(s.Context, hash, "remove tx item failure", func() error {
				return store.DeleteData(tx)
			})
			if needRetry {
				// Insert new data for the next retry
				bus.SafeCall(s.Context, tx.Hash, "insert data item failure", func() error {
					return store.InsertData(tx.Hash, tx.Data, tx.To)
				})
			}
		}
	}
}

func (s *Submitter) votePolyTx(db *store.Store, bridgeSdk *bridge.SDK) {
	s.wg.Add(1)
	defer s.wg.Done()
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.Done():
			log.Info("Neo3 poly tx voter is exiting now", "chain", s.name)
			return
		default:
		}

		select {
		case <-ticker.C:
			s.RetryWithData(db, s.vote.Batch)
		default:
		}

		var polyTx []*msg.Tx
		var paidPolyTx []*msg.Tx
		txs, err := db.LoadTxs(s.vote.Batch)
		if err != nil {
			log.Error("Failed to load txs from store", "err", err)
			continue
		}

		if len(txs) == 0 {
			time.Sleep(time.Second * 5)
			continue
		}

		checkFeeState := map[string]*bridge.CheckFeeRequest{}
		for _, tx := range txs {
			if uint64(time.Now().Unix()) < tx.Delay {
				continue
			}

			t := new(msg.Tx)
			err := t.Decode(string(tx.Value))
			if err != nil {
				log.Error("Tx vote decode tx failed", "src hash", tx.Hash.Hex(), "err", err)
				// delete from db
				bus.SafeCall(s.Context, t.PolyHash, "remove neo3 poly tx item failure", func() error {
					return db.DeleteTxs(tx)
				})
				continue
			}
			polyTx = append(polyTx, t)

			checkFeeState[t.PolyHash.Hex()] = &bridge.CheckFeeRequest{
				ChainId:  t.SrcChainId,
				TxId:     t.TxId,
				PolyHash: t.PolyHash.Hex(),
			}
		}

		// check fee
		if s.vote.CheckFee {
			log.Info("Sending check fee request", "size", len(checkFeeState), "chain", s.name)
			err = bridgeSdk.Node().CheckFee(checkFeeState)
			if err != nil {
				log.Error("check fee failed", "err", err)
				time.Sleep(time.Minute)
				continue
			}
			log.Info("check fee success")
			log.Json(log.INFO, checkFeeState)

			for _, tx := range polyTx {
				feeMin := float32(0)
				feePaid := float32(0)
				check := checkFeeState[tx.PolyHash.Hex()]
				if check != nil {
					tx.CheckFeeStatus = checkFeeState[tx.PolyHash.Hex()].Status
					feeMin = float32(check.Min)
					feePaid = float32(check.Paid)
					tx.PaidGas = float64(check.PaidGas)
				}

				if check.Pass() {
					log.Info("CheckFee pass", "poly_hash", tx.PolyHash, "min", feeMin, "paid", feePaid)
				} else if check.Skip() {
					log.Warn("Skipping poly for marked as not target in fee check", "poly_hash", tx.PolyHash)
					// delete from db
					bus.SafeCall(s.Context, tx.PolyHash, "remove skipped neo3 poly tx item failure", func() error {
						return db.DeleteTxs(store.NewTx(tx))
					})
					continue
				} else {
					log.Warn("CheckFee tx not paid or missing in bridge, delay for 3 minutes", "poly_hash", tx.PolyHash, "min", feeMin, "paid", feePaid)
					// delete tx from db then insert delayed tx
					bus.SafeCall(s.Context, tx.PolyHash, "remove neo3 poly tx item failure", func() error {
						return db.DeleteTxs(store.NewTx(tx))
					})
					bus.SafeCall(s.Context, tx.PolyHash, "put not paid tx back", func() error {
						time.Sleep(time.Second * 30) // avoid key existing error when inserting
						tx.Delay = uint64(time.Now().Unix() + 150)
						return db.InsertTxs([]*store.Tx{store.NewTx(tx)})
					})
					continue
				}
				paidPolyTx = append(paidPolyTx, tx)
			}
		} else {
			paidPolyTx = polyTx
		}

		if len(paidPolyTx) == 0 {
			time.Sleep(time.Second * 10)
			continue
		}

		for _, tx := range paidPolyTx {
			if tx.TxType != msg.POLY || tx.DstChainId != base.NEO3 {
				log.Error("Neo3 poly tx vote invalid msg type", "msgType", tx.TxType, "from chain", tx.SrcChainId, "to chain", tx.DstChainId, "src hash", tx.SrcHash, "poly hash", tx.PolyHash.Hex())
				continue
			}
			log.Info("Processing neo3 poly tx", "poly_hash", tx.PolyHash.Hex())

			rawNeoTmv, err := s.convertRawNeoTmv(tx)
			if err != nil {
				log.Error("convertRawNeoTmv error", "poly hash", tx.PolyHash.Hex(), "err", err)
				continue
			}

			tx.DstData, err = s.constructDstData(rawNeoTmv)
			if err != nil {
				log.Error("constructDstData error", "poly hash", tx.PolyHash.Hex(), "err", err)
				continue
			}
			tx.DstHash, err = s.wallet.SendTransaction(tx.DstData)
			if err != nil {
				if strings.Contains(err.Error(), "already executed") {
					log.Info("This neo3 poly tx is already executed", "poly_hash", tx.PolyHash.String())
					// delete from db
					bus.SafeCall(s.Context, tx.PolyHash, "remove neo3 poly tx item failure", func() error {
						return db.DeleteTxs(store.NewTx(tx))
					})
				} else {
					log.Error("Process neo3 poly tx error, delay for 3 minutes to retry", "poly_hash", tx.PolyHash.String(), "err", err)
					// delete tx from db then insert delayed tx
					bus.SafeCall(s.Context, tx.PolyHash, "remove neo3 poly tx item failure", func() error {
						return db.DeleteTxs(store.NewTx(tx))
					})
					bus.SafeCall(s.Context, tx.PolyHash, "put process failed tx back", func() error {
						time.Sleep(time.Second * 30) // avoid key existing error when inserting
						tx.Delay = uint64(time.Now().Unix() + 150)
						return db.InsertTxs([]*store.Tx{store.NewTx(tx)})
					})
					log.Error("Process neo3 poly tx error", "poly_hash", tx.PolyHash.String(), "err", err)
				}
				continue
			}

			log.Info("Vote neo3 poly tx", "hash", tx.DstHash, "poly hash", tx.PolyHash.Hex())
			bus.SafeCall(s.Context, tx.DstHash, "insert neo3 data item failure", func() error {
				return db.InsertData(msg.HexToHash(tx.DstHash), tx.DstData, ethcomm.Address{})
			})

			// delete from db
			bus.SafeCall(s.Context, tx.PolyHash, "remove neo3 poly tx item failure", func() error {
				return db.DeleteTxs(store.NewTx(tx))
			})
		}
	}
}

func (s *Submitter) checkSuccess(hash string) (success bool, err error) {
	res := s.sdk.Node().GetApplicationLog(hash)
	if res.HasError() {
		return false, fmt.Errorf(res.GetErrorInfo())
	}

	if len(res.Result.Executions) == 0 {
		return false, fmt.Errorf("GetApplicationLog failed. res: %+v", res)
	}
	for _, execution := range res.Result.Executions {
		if execution.VMState == "FAULT" {
			return false, fmt.Errorf("engine falted: %s", execution.Exception)
		}

		for _, notification := range execution.Notifications {
			u, _ := helper.UInt160FromString(notification.Contract)
			if "0x"+u.String() == s.neoCcmc && notification.EventName == VERIFY_AND_EXECUTE_TX_SUCCESS {
				log.Info("Submitted poly tx to neo3", "neo3 hash", hash)
				return true, nil
			}
		}
	}
	return true, nil
}
