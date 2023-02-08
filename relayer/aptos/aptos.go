package aptos

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/devfans/zion-sdk/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/aptos"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/portto/aptos-go-sdk/models"
	"golang.org/x/crypto/sha3"
	"strconv"
	"strings"
	"sync"
	"time"
)

const AptosTestnetChainID = 2
const AptosMainnetChainID = 1

type Submitter struct {
	context.Context
	wg     *sync.WaitGroup
	config *config.SubmitterConfig
	sdk    *aptos.SDK
	name   string
	ccm    string
	polyId uint64
	wallet *wallet.AptosWallet
}

func (s *Submitter) Init(config *config.SubmitterConfig) (err error) {
	s.config = config
	s.sdk, err = aptos.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	if err != nil {
		return
	}
	if config.Wallet != nil {
		sdk, e := aptos.WithOptions(config.ChainId, config.Wallet.Nodes, time.Minute, 1)
		if e != nil {
			return e
		}
		w := wallet.NewAptosWallet(config.Wallet, sdk)
		err = w.Init()
		if err != nil {
			return err
		}
		s.wallet = w
	}

	s.ccm = util.LowerHex(config.CCMContract)
	s.name = base.GetChainName(config.ChainId)
	s.polyId = zion.ReadChainID()
	return
}

func (s *Submitter) Submit(message msg.Message) error {
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
	log.Info("Starting submitter worker", "index", 0, "total", 1, "account", s.wallet.Address, "chain", s.name)
	go s.run(s.wallet, bus, delay, composer)
	return nil
}

func (s *Submitter) run(wallet *wallet.AptosWallet, mq bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer) error {
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
		log.Info("Processing poly tx", "poly_hash", tx.PolyHash.Hex(), "account", wallet.Address)
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
			if errors.Is(err, msg.ERR_APTOS_SEQUENCE_NUMBER_INVALID) {
				tsp := time.Now().Unix() + 60
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_LOW_BALANCE) {
				tsp := time.Now().Unix() + 60*10
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_APTOS_COIN_STORE_NOT_PUBLISHED) {
				tsp := time.Now().Unix() + 60*10
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_APTOS_TREASURY_NOT_EXIST) {
				tsp := time.Now().Unix() + 60*10
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else {
				tsp := time.Now().Unix() + 60*3
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			}
		} else {
			log.Info("Submitted poly tx", "poly_hash", tx.PolyHash.Hex(), "chain", s.name, "dst_hash", tx.DstHash)

			// Retry to verify a successful submit
			tsp := time.Now().Unix() + 60*3
			if tx.DstHash != "" {
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			}
		}
	}
}

func (s *Submitter) Process(m msg.Message, composer msg.PolyComposer) error {
	tx, ok := m.(*msg.Tx)
	if !ok {
		return fmt.Errorf("%s Proccess: Invalid poly tx cast %v", s.name, m)
	}
	return s.ProcessTx(tx, composer)
}

func (s *Submitter) ProcessTx(m *msg.Tx, compose msg.PolyComposer) (err error) {
	if m.Type() != msg.POLY {
		return fmt.Errorf("%s desired message is not poly tx %v", s.name, m.Type())
	}

	if m.DstChainId != s.config.ChainId {
		return fmt.Errorf("message dst chain does not match %v", m.DstChainId)
	}

	err = compose(m)
	if err != nil {
		return
	}
	return s.processPolyTx(m)
}

type Args struct {
	AssetAddress []byte
	ToAddress    []byte
	Value        uint64
}

func (a *Args) Deserialization(source *util.ZeroCopySource) error {
	assetAddress, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("Args deserialize assetAddress error")
	}
	toAddress, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("Args deserialize toAddress error")
	}
	value, eof := source.NextUint64()
	if eof {
		return fmt.Errorf("Args deserialize value error")
	}
	a.AssetAddress = assetAddress
	a.ToAddress = toAddress
	a.Value = value
	return nil
}

func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	txJson, _ := json.Marshal(tx)
	fmt.Printf("tx: %s\n", string(txJson))

	argsZS := util.NewZeroCopySource(tx.MerkleValue.MakeTxParam.Args)
	argsAssetAddress, eof := argsZS.NextVarBytes()
	if eof {
		return fmt.Errorf("%s failed to decode Args %v", s.name, err)
	}
	fmt.Println("argsAssetAddress=", string(argsAssetAddress))
	tx.ToAssetAddress = string(argsAssetAddress)
	return
}

func (s *Submitter) SubmitTx(tx *msg.Tx) (err error) {
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

	seed, err := hex.DecodeString(s.wallet.PrivateKey)
	if err != nil {
		return fmt.Errorf("decode private key error: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	authKey := sha3.Sum256(append(pub[:], 0x00))
	address := hex.EncodeToString(authKey[:])

	accountInfo, err := s.sdk.Node().GetAccount(s.Context, address)
	if err != nil {
		return fmt.Errorf("%w aptos GetAccount error: %s", msg.ERR_TX_EXEC_FAILURE, err)
	}

	tran := models.Transaction{}
	if base.ENV == "testnet" {
		tran.SetChainID(AptosTestnetChainID)
	} else {
		tran.SetChainID(AptosMainnetChainID)
	}
	tran.SetSender(address)

	contractAddr, _ := models.HexToAccountAddress(s.ccm)
	coinTypeTag, err := getAptosCoinTypeTag(tx.ToAssetAddress)
	if err != nil {
		return fmt.Errorf("getAptosCoinTypeTag error: %s", err)
	}
	fmt.Printf("getAptosCoinTypeTag result: %+v\n", coinTypeTag)

	functionName := "relay_unlock_tx"

	tran.SetPayload(models.EntryFunctionPayload{
		Module: models.Module{
			Address: contractAddr,
			Name:    "wrapper_v1",
		},
		Function:      functionName,
		TypeArguments: []models.TypeTag{coinTypeTag},
		Arguments: []interface{}{
			hsHeader,
			rawSeals,
			tx.PolyAccountProof,
			tx.PolyStorageProof,
			cctx,
		},
	})

	tran.SetExpirationTimestampSecs(uint64(time.Now().Add(2 * time.Minute).Unix()))
	tran.SetSequenceNumber(accountInfo.SequenceNumber)

	isExecuted, err := s.SimulateTransaction(&tran, priv, tx.DstHash)
	if err != nil {
		return err
	}
	if isExecuted {
		log.Info("ProcessPolyTx dst tx already relayed", "chain", s.name, "poly_hash", tx.PolyHash, "dst_hash", tx.DstHash)
		tx.DstHash = ""
		return nil
	}

	msgBytes, err := tran.GetSigningMessage()
	if err != nil {
		return fmt.Errorf("aptos GetSigningMessage error: %s", err)
	}
	signature := ed25519.Sign(priv, msgBytes)
	tran.SetAuthenticator(models.TransactionAuthenticatorEd25519{
		PublicKey: priv.Public().(ed25519.PublicKey),
		Signature: signature,
	})

	if tran.Error() != nil {
		return fmt.Errorf("compose aptos transaction failed. err: %v", tran.Error())
	}

	computedHash, err := tran.GetHash()
	if err != nil {
		return fmt.Errorf("aptos GetHash error: %s", err)
	}
	log.Info("aptos", "tx computedHash", computedHash)

	rawTx, err := s.sdk.Node().SubmitTransaction(s.Context, tran.UserTransaction)
	if err != nil {
		info := err.Error()
		if strings.Contains(info, "SEQUENCE_NUMBER_TOO_OLD") || strings.Contains(info, "SEQUENCE_NUMBER_TOO_NEW") {
			err = msg.ERR_APTOS_SEQUENCE_NUMBER_INVALID
		} else if strings.Contains(info, "INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE") {
			err = msg.ERR_LOW_BALANCE
		} else if strings.Contains(info, "ECOIN_STORE_NOT_PUBLISHED") {
			err = msg.ERR_APTOS_COIN_STORE_NOT_PUBLISHED
		} else if strings.Contains(info, "ETREASURY_NOT_EXIST") {
			err = msg.ERR_APTOS_TREASURY_NOT_EXIST
		}
	} else {
		log.Info("aptos", "script payload tx hash", rawTx.Hash)
		tx.DstHash = rawTx.Hash
	}

	return
}

func (s *Submitter) SimulateTransaction(tran *models.Transaction, priv ed25519.PrivateKey, hash string) (isExecuted bool, err error) {
	if hash != "" {
		tx, e := s.sdk.Node().GetTransactionByHash(s.Context, hash)
		if e != nil {
			return false, fmt.Errorf("aptos GetTransactionByHash failed. err: %v", e)
		}
		if tx.Success {
			return true, nil
		} else {
			log.Error("aptos tx failed", "hash", hash, "vm_status", tx.VmStatus)
		}
	}

	msgBytes, err := tran.GetSigningMessage()
	if err != nil {
		return false, fmt.Errorf("aptos GetSigningMessage error: %s", err)
	}
	signature := ed25519.Sign(priv, msgBytes)

	tran.SetAuthenticator(models.TransactionAuthenticatorEd25519{
		PublicKey: priv.Public().(ed25519.PublicKey),
		Signature: signature,
	})

	simulateTxResp, err := s.sdk.Node().SimulateTransaction(s.Context, tran.UserTransaction, true, true)
	//fmt.Printf("simulateTxResp: %+v\n", simulateTxResp)
	if err != nil || len(simulateTxResp) == 0 {
		return false, fmt.Errorf("aptos SimulateTransaction error: %s", err)
	}

	simulate := simulateTxResp[0]
	if !simulate.Success {
		if strings.Contains(simulate.VmStatus, "EALREADY_EXECUTED") {
			return true, nil
		} else {
			return false, fmt.Errorf("aptos SimulateTransaction failed. VmStatus: %s", simulate.VmStatus)
		}
	}

	tran.SetGasUnitPrice(uint64(101))

	gasUsed, err := strconv.ParseUint(simulate.GasUsed, 10, 32)
	if err != nil {
		log.Warn("aptos", "estimate gas limit failed, will use default gas limit. error", err)
		tran.SetMaxGasAmount(uint64(100000))
	}
	tran.SetMaxGasAmount(uint64(float32(gasUsed) * 1.5))
	return false, nil
}

func getAptosCoinTypeTag(toAssetAddress string) (models.TypeTag, error) {
	parts := strings.Split(toAssetAddress, "<")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid toAssetAddress: %s", toAssetAddress)
	}

	parts = strings.Split(strings.TrimSuffix(parts[1], ">"), "::")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid toAssetAddress: %s", toAssetAddress)
	}
	fmt.Printf("getAptosCoinTypeTag parts: %+v\n", parts)
	if len(parts[0])%2 == 1 {
		parts[0] = strings.Replace(parts[0], "0x", "0x0", 1)
	}
	addr, err := models.HexToAccountAddress(parts[0])
	if err != nil {
		return nil, fmt.Errorf("getAptosCoinTypeTag HexToAccountAddress failed. err: %s", err)
	}
	return models.TypeTagStruct{
		Address: addr,
		Module:  parts[1],
		Name:    parts[2],
	}, nil
}

func (s *Submitter) ProcessEpochs(epochs []*msg.Tx) error {
	functionName := "change_epoch"
	moduleName := "cross_chain_manager"
	for _, m := range epochs {
		if m.Type() != msg.POLY_EPOCH || m.PolyEpoch == nil {
			return fmt.Errorf("Invalid Poly epoch message %s", m.Encode())
		}
		epoch := m.PolyEpoch
		log.Info("Submitting poly epoch", "epoch", epoch.EpochId, "height", epoch.Height, "chain", s.name)

		seed, err := hex.DecodeString(s.wallet.PrivateKey)
		if err != nil {
			return fmt.Errorf("decode private key error: %v", err)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		authKey := sha3.Sum256(append(pub[:], 0x00))
		address := hex.EncodeToString(authKey[:])

		accountInfo, err := s.sdk.Node().GetAccount(s.Context, address)
		if err != nil {
			return fmt.Errorf("%w aptos GetAccount error: %s", msg.ERR_TX_EXEC_FAILURE, err)
		}

		tran := models.Transaction{}
		if base.ENV == "testnet" {
			tran.SetChainID(AptosTestnetChainID)
		} else {
			tran.SetChainID(AptosMainnetChainID)
		}
		tran.SetSender(address)

		contractAddr, _ := models.HexToAccountAddress(s.ccm)
		tran.SetPayload(models.EntryFunctionPayload{
			Module: models.Module{
				Address: contractAddr,
				Name:    moduleName,
			},
			Function: functionName,
			Arguments: []interface{}{
				epoch.Header,
				epoch.Seal,
			},
		})
		tran.SetExpirationTimestampSecs(uint64(time.Now().Add(2 * time.Minute).Unix()))
		tran.SetSequenceNumber(accountInfo.SequenceNumber)

		isExecuted, err := s.SimulateTransaction(&tran, priv, m.DstHash)
		if err != nil {
			return err
		}
		if isExecuted {
			log.Info("zion epoch already synced to Aptos", "chain", s.name, "epoch", epoch.EpochId, "height", epoch.Height)
			continue
		}

		msgBytes, err := tran.GetSigningMessage()
		if err != nil {
			return fmt.Errorf("aptos GetSigningMessage error: %s", err)
		}
		signature := ed25519.Sign(priv, msgBytes)
		tran.SetAuthenticator(models.TransactionAuthenticatorEd25519{
			PublicKey: priv.Public().(ed25519.PublicKey),
			Signature: signature,
		})

		if tran.Error() != nil {
			return fmt.Errorf("compose aptos transaction failed. err: %v", tran.Error())
		}

		rawTx, err := s.sdk.Node().SubmitTransaction(s.Context, tran.UserTransaction)
		if err != nil {
			return fmt.Errorf("Aptos epoch sync SubmitTransaction failed. epoch: %d, err: %v", epoch.EpochId, err)
		} else {
			log.Info("Aptos epoch sync", "epoch", epoch.EpochId, "hash", rawTx.Hash)
		}

		count := 20
	CONFIRM:
		for {
			tx, e := s.sdk.Node().GetTransactionByHash(s.Context, rawTx.Hash)
			if e != nil {
				count--
				e = fmt.Errorf("Aptos epoch sync GetTransactionByHash failed, hash: %s, err: %v", rawTx.Hash, e)
				//return fmt.Errorf("Aptos epoch sync GetTransactionByHash failed, hash: %s, err: %v", rawTx.Hash, e)
			} else {
				if tx.Success {
					log.Info("Aptos epoch sync tx confirmed", "epoch", epoch.EpochId, "hash", rawTx.Hash)
					break CONFIRM
				} else {
					return fmt.Errorf("Aptos epoch sync tx failed, hash: %s, VmStatus: %s", rawTx.Hash, tx.VmStatus)
				}
			}
			time.Sleep(time.Second * 3)
			if count <= 0 {
				return e
			}

		}
	}
	return nil
}

func (s *Submitter) GetPolyEpochStartHeight() (height uint64, err error) {
	var globalConfig aptos.CrossChainGlobalConfig
	err = s.sdk.Node().GetResourceWithCustomType(s.Context, s.ccm, fmt.Sprintf("%s::cross_chain_manager::CrossChainGlobalConfig", "0x"+strings.TrimPrefix(s.ccm, "0x")), &globalConfig)
	if err != nil {
		return 0, fmt.Errorf("aptos getPolyEpochStartHeight err: %v", err)
	}
	height, err = strconv.ParseUint(globalConfig.Data.CurEpochStartHeight, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("aptos parse CurEpochStartHeight err: %v", err)
	}
	return
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}
