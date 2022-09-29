package aptos

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/aptos"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly/common"
	"github.com/portto/aptos-go-sdk/models"
	"golang.org/x/crypto/sha3"
	"strings"
	"sync"
	"time"
)

const DevnetChainID = 34
const TestnetChainID = 2
const mainnetChainID = 1

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
	s.polyId = poly.ReadChainID()
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
	fmt.Printf("Submitter=%+v\n", s)
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
		log.Info("Processing poly tx", "poly_hash", tx.PolyHash, "account", wallet.Address)
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
			if errors.Is(err, msg.ERR_TX_EXEC_FAILURE) {
				tsp := time.Now().Unix() + 60*3
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_FEE_CHECK_FAILURE) {
				tsp := time.Now().Unix() + 10
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else {
				// todo analyze which err need to retry
				//tsp := time.Now().Unix() + 60
				//bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
				//bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx) })
			}
		} else {
			log.Info("Submitted poly tx", "poly_hash", tx.PolyHash, "chain", s.name, "dst_hash", tx.DstHash)
			// todo verify a successful submit
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

func (a *Args) Deserialization(source *common.ZeroCopySource) error {
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

	fmt.Printf("tx.MerkleValue: %+v\n", tx.MerkleValue)
	fmt.Printf("tx.MerkleValue.MakeTxParam: %+v\n", tx.MerkleValue.MakeTxParam)
	fmt.Printf("tx.Param: %+v\n", tx.Param)

	argsZS := common.NewZeroCopySource(tx.MerkleValue.MakeTxParam.Args)
	argsAssetAddress, eof := argsZS.NextVarBytes()
	if eof {
		return fmt.Errorf("%s failed to decode Args %v", s.name, err)
	}
	fmt.Println("argsAssetAddress=", string(argsAssetAddress))
	tx.ToAssetAddress = string(argsAssetAddress)

	//proof, err := hex.DecodeString(tx.AuditPath)
	//if err != nil {
	//	return fmt.Errorf("%s failed to decode audit path %v", s.name, err)
	//}
	//
	//rawHeader := tx.PolyHeader.GetMessage()
	//
	//headerProof, err := hex.DecodeString(tx.AnchorProof)
	//if err != nil {
	//	return fmt.Errorf("%s processPolyTx decode anchor proof hex error %v", s.name, err)
	//}
	//
	//var anchor []byte
	//if tx.AnchorHeader != nil {
	//	anchor = tx.AnchorHeader.GetMessage()
	//}
	//
	//headerSig := tx.PolySigs

	return
}

func (s *Submitter) SubmitTx(tx *msg.Tx) (err error) {
	ctx := context.Background()
	proof, err := hex.DecodeString(tx.AuditPath)
	if err != nil {
		return fmt.Errorf("%s failed to decode audit path %v", s.name, err)
	}

	rawHeader := tx.PolyHeader.GetMessage()

	headerProof, err := hex.DecodeString(tx.AnchorProof)
	if err != nil {
		return fmt.Errorf("%s processPolyTx decode anchor proof hex error %v", s.name, err)
	}

	var anchor []byte
	if tx.AnchorHeader != nil {
		anchor = tx.AnchorHeader.GetMessage()
	}

	headerSig := tx.PolySigs

	//fileBytes, err := os.ReadFile("./wrapper_v1.mv")
	//if err != nil {
	//	return fmt.Errorf("read contract mv file error: %v", err)
	//}

	seed, err := hex.DecodeString(s.wallet.PrivateKey)
	if err != nil {
		return fmt.Errorf("decode private key error: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	authKey := sha3.Sum256(append(pub[:], 0x00))
	address := hex.EncodeToString(authKey[:])

	accountInfo, err := s.sdk.Node().GetAccount(ctx, address)
	if err != nil {
		return fmt.Errorf("%w aptos GetAccount error: %s", msg.ERR_TX_EXEC_FAILURE, err)
	}

	tran := models.Transaction{}
	if base.ENV == "testnet" {
		tran.SetChainID(TestnetChainID)
	} else {
		tran.SetChainID(mainnetChainID)
	}
	tran.SetSender(address)
	//tran.SetPayload(models.ScriptPayload{
	//	Code: fileBytes,
	//	Arguments: []models.TransactionArgument{
	//		models.TxArgU8Vector{Bytes: proof},
	//		models.TxArgU8Vector{Bytes: rawHeader},
	//		models.TxArgU8Vector{Bytes: headerProof},
	//		models.TxArgU8Vector{Bytes: anchor},
	//		models.TxArgU8Vector{Bytes: headerSig},
	//	},
	//})

	contractAddr, _ := models.HexToAccountAddress(s.ccm)
	coinTypeTag, err := getAptosCoinTypeTag(tx.ToAssetAddress)
	if err != nil {
		return fmt.Errorf("getAptosCoinTypeTag error: %s", err)
	}
	fmt.Printf("getAptosCoinTypeTag result: %+v\n", coinTypeTag)

	functionName := "relay_unlock_tx"
	//if base.ENV == "testnet" {
	//	functionName = "realy_unlock_tx"
	//}

	tran.SetPayload(models.EntryFunctionPayload{
		Module: models.Module{
			Address: contractAddr,
			Name:    "wrapper_v1",
		},
		Function:      functionName,
		TypeArguments: []models.TypeTag{coinTypeTag},
		Arguments: []interface{}{
			proof,
			rawHeader,
			headerProof,
			anchor,
			headerSig,
		},
	})

	tran.SetExpirationTimestampSecs(uint64(time.Now().
		Add(3 * time.Minute).Unix())).
		SetGasUnitPrice(uint64(100)).
		SetMaxGasAmount(uint64(50000)).
		SetSequenceNumber(accountInfo.SequenceNumber)
	if tran.Error() != nil {
		return fmt.Errorf("compose aptos transaction failed. err: %v", err)
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
	computedHash, err := tran.GetHash()
	if err != nil {
		return fmt.Errorf("aptos GetHash error: %s", err)
	}
	log.Info("aptos", "tx computedHash", computedHash)

	simulateTxResp, err := s.sdk.Node().SimulateTransaction(ctx, tran.UserTransaction, true, true)
	if err != nil {
		return fmt.Errorf("aptos SimulateTransaction error: %s", err)
	}
	// simulateTxResp: GasUnitPrice:100 GasUsed:1454 SetMaxGasAmount // todo estimate gas limit

	fmt.Printf("simulateTxResp: %+v\n", simulateTxResp)

	rawTx, err := s.sdk.Node().SubmitTransaction(ctx, tran.UserTransaction)
	if err != nil {
		return fmt.Errorf("aptos SubmitTransaction error: %s", err)
	}

	log.Info("aptos", "script payload tx hash", rawTx.Hash)

	return
}

func getAptosCoinTypeTag(toAssetAddress string) (models.TypeTag, error) {
	parts := strings.Split(toAssetAddress, "<")
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

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}
