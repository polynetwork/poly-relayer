package eth

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/polynetwork/bridge-common/abi/eccd_abi"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/eth"
	"github.com/polynetwork/bridge-common/wallet"
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
	s.sdk, err = eth.NewSDK(config.ChainId, config.Nodes, time.Minute, 1)
	if err != nil {
		return
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
	var gasPrice *big.Int
	var gasPriceX *big.Float
	var ok bool
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
	return s.Send(s.ccm, big.NewInt(0), tx.DstGasLimit, gasPrice, gasPriceX, tx.DstData)
}

func (s *Submitter) Send(addr common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, gasPriceX *big.Float, data []byte) (err error) {
	return s.wallet.Send(addr, amount, gasLimit, gasPrice, gasPriceX, data)
}

func (s *Submitter) Hook(ctx context.Context, wg *sync.WaitGroup, ch <-chan msg.Message) error {
	s.Context = ctx
	s.wg = wg
	return nil
}

func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	txId, err := tx.GetTxId()
	if err != nil {
		return
	}
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk.Node())
	if err != nil {
		return
	}
	exist, err := ccd.CheckIfFromChainTxExist(nil, tx.SrcChainId, txId)
	if err != nil {
		return err
	}

	if exist {
		logs.Info("%s processPolyTx dst tx already relayed, tx id occupied %s", s.name, tx.TxId)
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
	tx.DstData, err = s.abi.Pack("verifyHeaderAndExecuteTx", tx.AuditPath, tx.PolyHeader.GetMessage(), proof, anchor, tx.DstSigs)
	if err != nil {
		err = fmt.Errorf("%s processPolyTx pack tx error %v", err)
		return err
	}
	return s.submit(tx)
}

func (s *Submitter) Process(m msg.Message, compose msg.PolyComposer) (err error) {
	if m.Type() != msg.POLY {
		return
	}
	tx, ok := m.(*msg.Tx)
	if !ok {
		return fmt.Errorf("%s Proccess: Invalid poly tx cast %v", s.name, m)
	}
	if !ok || tx.DstChainId != s.config.ChainId {
		return nil
	}
	err = compose(tx)
	if err != nil {
		return
	}
	return s.processPolyTx(tx)
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}
