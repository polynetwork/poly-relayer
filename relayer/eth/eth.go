package eth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"github.com/polynetwork/bridge-common/abi/eccd_abi"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"github.com/polynetwork/bridge-common/base"
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
			return fmt.Errorf("%s submit invalid gas price %s", tx.DstGasPrice)
		}
	}
	if tx.DstGasPriceX != "" {
		gasPriceX, ok = new(big.Float).SetString(tx.DstGasPriceX)
		if !ok {
			return fmt.Errorf("%s submit invalid gas priceX %s", tx.DstGasPriceX)
		}
	}
	var err error
	if tx.DstSender != nil {
		account := tx.DstSender.(*accounts.Account)
		tx.DstHash, err = s.wallet.SendWithAccount(*account, s.ccm, big.NewInt(0), tx.DstGasLimit, gasPrice, gasPriceX, tx.DstData)
	} else {
		tx.DstHash, err = s.wallet.Send(s.ccm, big.NewInt(0), tx.DstGasLimit, gasPrice, gasPriceX, tx.DstData)
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

func (s *Submitter) GetPolyKeepers() (keepers []byte, err error) {
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk.Node())
	if err != nil {
		return
	}
	return ccd.GetCurEpochConPubKeyBytes(nil)
}

func (s *Submitter) GetPolyEpochStartHeight() (height uint32, err error) {
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk.Node())
	if err != nil {
		return
	}
	return ccd.GetCurEpochStartHeight(nil)
}

func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk.Node())
	if err != nil {
		return
	}
	txId := [32]byte{}
	copy(txId[:], tx.MerkleValue.TxHash[:32])
	exist, err := ccd.CheckIfFromChainTxExist(nil, tx.SrcChainId, txId)
	if err != nil {
		return err
	}

	if exist {
		log.Info("ProcessPolyTx dst tx already relayed, tx id occupied", "chain", s.name, "poly_hash", tx.PolyHash)
		tx.DstHash = ""
		return nil
	}

	proof, err := hex.DecodeString(tx.AnchorProof)
	if err != nil {
		return fmt.Errorf("%s processPolyTx decode anchor proof hex error %v", s.name, err)
	}

	var anchor []byte
	if tx.AnchorHeader != nil {
		anchor = tx.AnchorHeader.GetMessage()
	}
	path, err := hex.DecodeString(tx.AuditPath)
	if err != nil {
		return fmt.Errorf("%s failed to decode audit path %v", s.name, err)
	}
	tx.DstData, err = s.abi.Pack("verifyHeaderAndExecuteTx", path, tx.PolyHeader.GetMessage(), proof, anchor, tx.PolySigs)
	if err != nil {
		err = fmt.Errorf("%s processPolyTx pack tx error %v", s.name, err)
		return err
	}
	return s.submit(tx)
}

func (s *Submitter) ProcessTx(m *msg.Tx, compose msg.PolyComposer) (err error) {
	if m.Type() != msg.POLY {
		return fmt.Errorf("%s desired message is not poly tx %v", m.Type())
	}

	switch v := m.DstSender.(type) {
	case string:
		for _, a := range s.wallet.Accounts() {
			if util.LowerHex(a.Address.String()) == util.LowerHex(v) {
				m.DstSender = &a
				break
			}
		}
	}

	if m.DstChainId != s.config.ChainId {
		return fmt.Errorf("%s message dst chain does not match %v", m.DstChainId)
	}
	m.DstPolyEpochStartHeight, err = s.GetPolyEpochStartHeight()
	if err != nil {
		return fmt.Errorf("%s fetch dst chain poly epoch height error %v", s.name, err)
	}
	m.DstPolyKeepers, err = s.GetPolyKeepers()
	if err != nil {
		return fmt.Errorf("%s fetch dst chain poly keepers error %v", s.name, err)
	}
	err = compose(m)
	if err != nil {
		return
	}
	err = s.processPolyTx(m)
	if err != nil {
		info := err.Error()
		if strings.Contains(info, "business contract failed") {
			err = fmt.Errorf("%w tx exec error %v", msg.ERR_TX_EXEC_FAILURE, err)
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
		log.Info("Processing poly tx", "poly_hash", tx.PolyHash, "account", account.Address)
		tx.DstSender = &account
		err = s.ProcessTx(tx, compose)
		if err != nil {
			log.Error("Process poly tx error", "chain", s.name, "poly_hash", tx.PolyHash, "err", err)
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
			} else if errors.Is(err, msg.ERR_FEE_CHECK_FAILURE) {
				tsp := time.Now().Unix() + 10
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
			log.Info("Submitted poly tx", "poly_hash", tx.PolyHash, "chain", s.name, "dst_hash", tx.DstHash)

			// Retry to verify a successful submit
			tsp := int64(0)
			switch s.config.ChainId {
			case base.MATIC, base.PLT:
				tsp = time.Now().Unix() + 60*3
			case base.ARBITRUM, base.XDAI, base.OPTIMISM, base.AVA, base.FANTOM, base.RINKEBY, base.BOBA, base.PIXIE:
				tsp = time.Now().Unix() + 60*25
			case base.BSC, base.HECO, base.OK:
				tsp = time.Now().Unix() + 60*4
			case base.ETH:
				tsp = time.Now().Unix() + 60*6
			}
			if tsp > 0 && tx.DstHash != "" {
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
