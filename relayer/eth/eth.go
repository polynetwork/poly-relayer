package eth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/polynetwork/bridge-common/abi/eccd_abi"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/devfans/zion-sdk/core/types"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/bridge"
	"github.com/polynetwork/bridge-common/chains/eth"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Submitter struct {
	context.Context
	wg     *sync.WaitGroup
	config *config.SubmitterConfig
	sdk    *eth.SDK
	name   string
	ccd    common.Address
	ccm    common.Address
	abi    abi.ABI
	wallet wallet.IWallet
	// eccd   *eccd_abi.EthCrossChainData
}

func (s *Submitter) Init(config *config.SubmitterConfig) (err error) {
	s.config = config
	s.sdk, err = eth.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	if err != nil {
		return
	}
	if config.Wallet != nil {
		sdk, err := eth.WithOptions(config.ChainId, config.Wallet.Nodes, time.Minute, 1)
		if err != nil {
			return err
		}
		w := wallet.New(config.Wallet, sdk)
		err = w.Init()
		if err != nil {
			return err
		}
		if s.config.ChainId == base.ETH {
			s.wallet = w.Upgrade()
		} else {
			s.wallet = w
		}
	}
	s.name = base.GetChainName(config.ChainId)
	s.ccd = common.HexToAddress(config.CCDContract)
	s.ccm = common.HexToAddress(config.CCMContract)
	s.abi, err = abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	return
}

func (s *Submitter) Submit(msg msg.Message) error {
	return nil
}

func (s *Submitter) submit(tx *msg.Tx) error {
	if len(tx.DstData) == 0 {
		return nil
	}
	var (
		gasPrice  *big.Int
		gasPriceX *big.Float
		ok        bool
	)
	if tx.DstGasPrice != "" {
		gasPrice, ok = new(big.Int).SetString(tx.DstGasPrice, 10)
		if !ok {
			return fmt.Errorf("submit invalid gas price %s", tx.DstGasPrice)
		}
	}
	if tx.DstGasPriceX != "" {
		gasPriceX, ok = new(big.Float).SetString(tx.DstGasPriceX)
		if !ok {
			return fmt.Errorf("submit invalid gas priceX %s", tx.DstGasPriceX)
		}
	}
	var (
		err     error
		account accounts.Account
	)
	if tx.DstSender != nil {
		acc := tx.DstSender.(*accounts.Account)
		account = *acc
	} else {
		account, _, _ = s.wallet.Select()
	}

	if tx.CheckFeeOff || tx.CheckFeeStatus != bridge.PAID_LIMIT {
		tx.DstHash, err = s.wallet.SendWithAccount(account, s.ccm, big.NewInt(0), tx.DstGasLimit, gasPrice, gasPriceX, tx.DstData)
	} else {
		maxLimit, _ := big.NewFloat(tx.PaidGas).Int(nil)
		tx.DstHash, err = s.wallet.SendWithMaxLimit(s.sdk.ChainID, account, s.ccm, big.NewInt(0), maxLimit, gasPrice, gasPriceX, tx.DstData)
	}

	return err
}

func (s *Submitter) Send(addr common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, gasPriceX *big.Float, data []byte) (hash string, err error) {
	return s.wallet.Send(addr, amount, gasLimit, gasPrice, gasPriceX, data)
}

func (s *Submitter) Hook(ctx context.Context, wg *sync.WaitGroup, ch <-chan msg.Message) error {
	s.Context = ctx
	s.wg = wg
	return nil
}

func (s *Submitter) GetPolyEpochStartHeight(uint64) (height uint64, err error) {
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk.Node())
	if err != nil {
		return
	}
	h, err := ccd.GetCurEpochStartHeight(nil)
	return uint64(h), err
}

func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk.Node())
	if err != nil {
		log.Error("NewEthCrossChainData failed", "polyHash", tx.PolyHash.Hex(), "err", err)
		return
	}
	txId := [32]byte{}
	copy(txId[:], tx.MerkleValue.TxHash[:32])
	exist, err := ccd.CheckIfFromChainTxExist(nil, tx.SrcChainId, txId)
	if err != nil {
		log.Error("CheckIfFromChainTxExist failed", "polyHash", tx.PolyHash.Hex(), "err", err)
		return err
	}

	if exist {
		log.Info("ProcessPolyTx dst tx already relayed, tx id occupied", "chain", s.name, "poly_hash", tx.PolyHash)
		tx.DstHash = ""
		return nil
	}

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

	tx.DstData, err = s.abi.Pack(
		"verifyHeaderAndExecuteTx",
		hsHeader, rawSeals, tx.PolyAccountProof, tx.PolyStorageProof, cctx,
	)
	if err != nil {
		err = fmt.Errorf("%s processPolyTx pack tx error %v", s.name, err)
		return err
	}
	return
}

func (s *Submitter) ProcessEpochs(epochs []*msg.Tx) (err error) {
	for _, m := range epochs {
		if m.Type() != msg.POLY_EPOCH || m.PolyEpoch == nil {
			err = fmt.Errorf("Invalid Poly epoch message %s", m.Encode())
			return
		}
		epoch := m.PolyEpoch
		log.Info("Submitting poly epoch", "epoch", epoch.EpochId, "height", epoch.Height, "chain", s.name)

		m.DstData, err = s.abi.Pack(
			"changeEpoch", epoch.Header, epoch.Seal,
		)
		if err != nil {
			err = fmt.Errorf("%s processPolyEpoch pack tx error %v", s.name, err)
			return err
		}
		err = s.submit(m)
		if err != nil {
			return
		}

		var height uint64
		var pending bool
	CONFIRM:
		for {
			hash := msg.Hash(m.DstHash)
			height, _, pending, err = s.sdk.Node().Confirm(hash, 0, 10)
			if height > 0 {
				log.Info("Submitted epoch updates", "chain", s.name, "hash", hash.String(), "height", height)
				break CONFIRM
			}
			if err == nil && !pending {
				err = fmt.Errorf("failed to find the transaction chain=%s, %v", s.name, err)
			} else {
				err = fmt.Errorf("tx wait confirm timeout chain=%s, hash=%s, pending=%v, err=%v", s.name, hash.String(), pending, err)
			}
			return
		}

	}
	return nil
}

func (s *Submitter) ProcessTx(m *msg.Tx, compose msg.PolyComposer) (err error) {
	if m.Type() != msg.POLY {
		return fmt.Errorf("%s desired message is not poly tx %v", s.name, m.Type())
	}

	if m.DstChainId != s.config.ChainId {
		return fmt.Errorf("%s message dst chain does not match %v", s.name, m.DstChainId)
	}
	m.DstPolyEpochStartHeight, err = s.GetPolyEpochStartHeight(0)
	if err != nil {
		return fmt.Errorf("%s fetch dst chain poly epoch height error %v", s.name, err)
	}
	err = compose(m)
	if err != nil {
		log.Error("compose failed", "polyHash", m.PolyHash.Hex(), "err", err)
		return
	}
	err = s.processPolyTx(m)
	return
}

func (s *Submitter) SubmitTx(tx *msg.Tx) (err error) {
	switch v := tx.DstSender.(type) {
	case string:
		for _, a := range s.wallet.Accounts() {
			if util.LowerHex(a.Address.String()) == util.LowerHex(v) {
				tx.DstSender = &a
				break
			}
		}
	}
	err = s.submit(tx)
	if err != nil {
		info := err.Error()
		if strings.Contains(info, "business contract failed") {
			err = fmt.Errorf("%w tx exec error %v", msg.ERR_TX_EXEC_FAILURE, err)
		} else if strings.Contains(info, "higher than max limit") || strings.Contains(info, "max limit is zero or missing") {
			err = fmt.Errorf("%w %v", msg.ERR_PAID_FEE_TOO_LOW, err)
		} else if strings.Contains(info, "always failing") {
			err = fmt.Errorf("%w tx exec error %v", msg.ERR_TX_EXEC_ALWAYS_FAIL, err)
		} else if strings.Contains(info, "insufficient funds") || strings.Contains(info, "exceeds allowance") {
			err = msg.ERR_LOW_BALANCE
		}
	}
	return
}

func (s *Submitter) Process(m msg.Message, compose msg.PolyComposer) (err error) {
	tx, ok := m.(*msg.Tx)
	if !ok {
		return fmt.Errorf("%s Proccess: Invalid poly tx cast %v", s.name, m)
	}
	return s.ProcessTx(tx, compose)
}

func (s *Submitter) run(account accounts.Account, mq bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer) error {
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
			log.Warn("Bus pop nil?", "chain", s.name)
			time.Sleep(time.Second)
			continue
		}
		tx.DstSender = &account
		if tx.Type() == msg.POLY {
			log.Info("Processing poly tx", "poly_hash", tx.PolyHash.Hex(), "account", account.Address)
			err = s.ProcessTx(tx, compose)
			if err == nil {
				err = s.SubmitTx(tx)
				if err != nil {
					log.Error("SubmitTx failed", "polyHash", tx.PolyHash.Hex(), "err", err)
				}
			} else {
				log.Error("ProcessTx failed", "polyHash", tx.PolyHash.Hex(), "err", err)
			}
		} else if tx.Type() == msg.POLY_EPOCH {
			log.Info("Processing poly epoch", "poly_epoch", tx.PolyEpoch.EpochId, "account", account.Address)
			err = s.ProcessEpochs([]*msg.Tx{tx})
		}
		if err != nil {
			log.Error("Process poly tx error", "chain", s.name, "poly_hash", tx.PolyHash.Hex(), "err", err)
			log.Json(log.ERROR, tx)
			if errors.Is(err, msg.ERR_INVALID_TX) || errors.Is(err, msg.ERR_TX_BYPASS) {
				log.Error("Skipped poly tx for error", "poly_hash", tx.PolyHash, "err", err)
				continue
			}
			tx.Attempts++
			// TODO: retry with increased gas price?
			if errors.Is(err, msg.ERR_TX_EXEC_FAILURE) || errors.Is(err, msg.ERR_TX_EXEC_ALWAYS_FAIL) {
				tsp := time.Now().Unix() + 60*3
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_FEE_CHECK_FAILURE) || err == msg.ERR_EPOCH_MISS {
				tsp := time.Now().Unix() + 10
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_PAID_FEE_TOO_LOW) {
				tsp := time.Now().Unix() + 60*10
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else {
				tsp := time.Now().Unix() + 1
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
				if errors.Is(err, msg.ERR_LOW_BALANCE) {
					log.Info("Low wallet balance detected", "chain", s.name, "account", account.Address)
					s.WaitForBalance(account.Address)
				}
			}
		} else {
			log.Info("Submitted poly tx", "poly_hash", tx.PolyHash.Hex(), "chain", s.name, "dst_hash", tx.DstHash)
			// Retry to verify a successful submit
			after := base.CheckAfter(s.config.ChainId)
			if after > 0 && tx.DstHash != "" {
				tsp := time.Now().Unix() + after
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			}
		}
	}
}

func (s *Submitter) WaitForBalance(address common.Address) {
	for {
		balance, err := s.wallet.GetBalance(address)
		hasBalance := wallet.HasBalance(s.config.ChainId, balance)
		log.Info("Wallet balance check", "chain", s.name, "account", address, "has_balance", hasBalance, "err", err)
		if hasBalance {
			return
		}
		select {
		case <-time.After(time.Minute):
		case <-s.Done():
			return
		}
	}
}

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, bus bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer) error {
	s.Context = ctx
	s.wg = wg
	accounts := s.wallet.Accounts()
	if len(accounts) == 0 {
		log.Warn("No account available for submitter workers", "chain", s.name)
	}
	for i, a := range accounts {
		log.Info("Starting submitter worker", "index", i, "total", len(accounts), "account", a.Address, "chain", s.name)
		go s.run(a, bus, delay, compose)
	}
	return nil
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}
