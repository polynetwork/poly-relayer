package starcoin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/devfans/zion-sdk/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/starcoin"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	starcoin_client "github.com/starcoinorg/starcoin-go/client"
	starcoin_types "github.com/starcoinorg/starcoin-go/types"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Submitter struct {
	context.Context
	wg     *sync.WaitGroup
	config *config.SubmitterConfig
	sdk    *starcoin.SDK
	name   string
	ccm    string
	polyId uint64
	wallet *StarcoinWallet
}

func (this *Submitter) Init(config *config.SubmitterConfig) (err error) {
	this.config = config
	this.sdk, err = starcoin.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	if err != nil {
		return
	}
	if config.Wallet != nil {
		sdk, e := starcoin.WithOptions(config.ChainId, config.Wallet.Nodes, time.Minute, 1)
		if e != nil {
			return e
		}
		w := NewStarcoinWallet(config.Wallet, sdk)
		err = w.Init()
		if err != nil {
			return err
		}
		this.wallet = w
	}

	this.ccm = util.LowerHex(config.CCMContract)
	this.name = base.GetChainName(config.ChainId)
	this.polyId = zion.ReadChainID()
	return
}

func (this *Submitter) Submit(message msg.Message) error {
	return nil
}

func (this *Submitter) Hook(ctx context.Context, wg *sync.WaitGroup, ch <-chan msg.Message) error {
	this.Context = ctx
	this.wg = wg
	return nil
}

func (this *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, bus bus.TxBus, delay bus.DelayedTxBus, composer msg.PolyComposer) error {
	this.Context = ctx
	this.wg = wg
	log.Info("Starting submitter worker", "index", 0, "total", 1, "account", this.wallet.Address, "chain", this.name)
	go this.run(this.wallet, bus, delay, composer)
	return nil
}

func (this *Submitter) run(wallet *StarcoinWallet, mq bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer) error {
	this.wg.Add(1)
	defer this.wg.Done()
	for {
		select {
		case <-this.Done():
			log.Info("Submitter is exiting now", "chain", this.name)
			return nil
		default:
		}
		tx, err := mq.Pop(this.Context)
		if err != nil {
			log.Error("Bus pop error", "err", err)
			continue
		}
		if tx == nil {
			time.Sleep(time.Second)
			continue
		}
		log.Info("Processing poly tx", "poly_hash", tx.PolyHash.Hex(), "account", wallet.Address)
		err = this.ProcessTx(tx, compose)
		if err == nil {
			err = this.SubmitTx(tx)
		}
		if err != nil {
			log.Error("Process poly tx error", "chain", this.name, "err", err)
			log.Json(log.ERROR, tx)
			if errors.Is(err, msg.ERR_INVALID_TX) || errors.Is(err, msg.ERR_TX_BYPASS) {
				log.Error("Skipped poly tx for error", "poly_hash", tx.PolyHash, "err", err)
				continue
			}
			tx.Attempts++
			if errors.Is(err, msg.ERR_STARCOIN_SEQUENCE_NUMBER_INVALID) {
				tsp := time.Now().Unix() + 60
				bus.SafeCall(this.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_LOW_BALANCE) {
				tsp := time.Now().Unix() + 60*10
				bus.SafeCall(this.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_STARCOIN_COIN_STORE_NOT_PUBLISHED) {
				tsp := time.Now().Unix() + 60*10
				bus.SafeCall(this.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_STARCOIN_TREASURY_NOT_EXIST) {
				tsp := time.Now().Unix() + 60*10
				bus.SafeCall(this.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else {
				tsp := time.Now().Unix() + 60*3
				bus.SafeCall(this.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			}
		} else {
			log.Info("Submitted poly tx", "poly_hash", tx.PolyHash.Hex(), "chain", this.name, "dst_hash", tx.DstHash)

			// Retry to verify a successful submit
			tsp := time.Now().Unix() + 60*3
			if tx.DstHash != "" {
				bus.SafeCall(this.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			}
		}
	}
}

func (this *Submitter) Process(m msg.Message, composer msg.PolyComposer) error {
	tx, ok := m.(*msg.Tx)
	if !ok {
		return fmt.Errorf("%s Proccess: Invalid poly tx cast %v", this.name, m)
	}
	return this.ProcessTx(tx, composer)
}

func (this *Submitter) ProcessTx(m *msg.Tx, compose msg.PolyComposer) (err error) {
	if m.Type() != msg.POLY {
		return fmt.Errorf("%s desired message is not poly tx %v", this.name, m.Type())
	}

	if m.DstChainId != this.config.ChainId {
		return fmt.Errorf("message dst chain does not match %v", m.DstChainId)
	}

	err = compose(m)
	if err != nil {
		return
	}
	return this.processPolyTx(m)
}

func (this *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	txJson, _ := json.Marshal(tx)
	fmt.Printf("tx: %s\n", string(txJson))

	argsZS := util.NewZeroCopySource(tx.MerkleValue.MakeTxParam.Args)
	argsAssetAddress, eof := argsZS.NextVarBytes()
	if eof {
		return fmt.Errorf("%s failed to decode Args %v", this.name, err)
	}
	fmt.Println("argsAssetAddress=", string(argsAssetAddress))
	tx.ToAssetAddress = string(argsAssetAddress)
	return
}

func (this *Submitter) ExecuteScriptFunction(
	moduleId starcoin_types.ModuleId,
	functionName string,
	typeArgs []starcoin_types.TypeTag,
	args [][]byte) (string, error) {

	payload := starcoin_types.TransactionPayload__ScriptFunction{
		Value: starcoin_types.ScriptFunction{
			Module:   moduleId,
			Function: starcoin_types.Identifier(functionName),
			TyArgs:   typeArgs,
			Args:     args,
		}}

	gasPrice, err := this.sdk.Node().GetGasUnitPrice(context.Background())
	if err != nil {
		return "", fmt.Errorf("starcoin GetGas price failed :%s", err.Error())
	}

	accountNonce, err := this.sdk.Node().GetAccountSequenceNumber(this.Context, this.wallet.address())
	if err != nil {
		return "", fmt.Errorf("%w Starcoin GetAccount nonce error: %s", msg.ERR_TX_EXEC_FAILURE, err)
	}

	gasLimit := starcoin_client.DEFAULT_MAX_GAS_AMOUNT * 4
	rawTransaction, err := this.sdk.Node().BuildRawUserTransaction(
		context.Background(),
		this.wallet.Address,
		&payload,
		gasPrice,
		uint64(gasLimit),
		accountNonce)
	if err != nil {
		return "", fmt.Errorf("starcoin Submittx | BuildRawUserTransaction error: %s", err.Error())
	}

	pubKey := this.wallet.asPublicKey()
	pubKeyStr := hex.EncodeToString(pubKey)
	log.Info("starcoin Submittx | Publickey: ", pubKeyStr, ". ")

	dryResult, err := this.sdk.Node().DryRunRaw(context.Background(), *rawTransaction, pubKey)
	if err != nil {
		return "", fmt.Errorf("starcoin Submittx | DryRunRaw error: %s", err.Error())
	}

	if dryResult.Status != "Executed" {
		return "", fmt.Errorf("starcoin Submittx | DryRunRaw error: %s", dryResult.Status)
	}

	return this.sdk.Node().SubmitTransaction(context.Background(), this.wallet.asPrivateKey(), rawTransaction)
}

func (this *Submitter) SubmitTx(tx *msg.Tx) (err error) {
	cctx, err := hex.DecodeString(tx.PolyParam)
	if err != nil || len(cctx) == 0 {
		return fmt.Errorf("poly param merke value missing or invalid")
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

	log.Info("Before commit relayer transaction from zion ",
		" \nhsHeader: ", hex.EncodeToString(hsHeader),
		"\nrawSeals: ", hex.EncodeToString(rawSeals),
		"\n tx.PolyAccountProof: ", hex.EncodeToString(tx.PolyAccountProof),
		"\n tx.PolyStorageProof: ", hex.EncodeToString(tx.PolyStorageProof),
		"\n cctx: ", hex.EncodeToString(cctx))

	coinTypeTag, err := getAssetCoinTypeTag(tx.ToAssetAddress)
	if err != nil {
		return fmt.Errorf("getAssetCoinTypeTag error: %s", err)
	}

	rawTx, err := this.ExecuteScriptFunction(
		starcoin_types.ModuleId{Address: this.wallet.Address, Name: "zion_lock_proxy_script"},
		"relay_unlock_tx",
		[]starcoin_types.TypeTag{coinTypeTag},
		[][]byte{
			encode_u8vector_argument(hsHeader),
			encode_u8vector_argument(rawSeals),
			encode_u8vector_argument(tx.PolyAccountProof),
			encode_u8vector_argument(tx.PolyStorageProof),
			encode_u8vector_argument(cctx),
		})

	if err != nil {
		info := err.Error()
		if strings.Contains(info, "SEQUENCE_NUMBER_TOO_OLD") || strings.Contains(info, "SEQUENCE_NUMBER_TOO_NEW") {
			err = msg.ERR_STARCOIN_SEQUENCE_NUMBER_INVALID
		} else if strings.Contains(info, "INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE") {
			err = msg.ERR_LOW_BALANCE
		} else if strings.Contains(info, "ECOIN_STORE_NOT_PUBLISHED") {
			err = msg.ERR_STARCOIN_COIN_STORE_NOT_PUBLISHED
		} else if strings.Contains(info, "ETREASURY_NOT_EXIST") {
			err = msg.ERR_STARCOIN_TREASURY_NOT_EXIST
		}
	} else {
		log.Info("starcoin", "script payload tx hash", rawTx)
		tx.DstHash = rawTx
	}
	return
}

func getAssetCoinTypeTag(toAssetAddress string) (starcoin_types.TypeTag, error) {
	parts := strings.Split(toAssetAddress, "<")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid toAssetAddress: %s", toAssetAddress)
	}

	parts = strings.Split(strings.TrimSuffix(parts[1], ">"), "::")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid toAssetAddress: %s", toAssetAddress)
	}

	if len(parts[0])%2 == 1 {
		parts[0] = strings.Replace(parts[0], "0x", "0x0", 1)
	}
	addr, err := starcoin_types.ToAccountAddress(parts[0])
	if err != nil {
		return nil, fmt.Errorf("getAssetCoinTypeTag HexToAccountAddress failed. err: %s", err)
	}

	return &starcoin_types.TypeTag__Struct{
		Value: starcoin_types.StructTag{
			Address: *addr,
			Module:  starcoin_types.Identifier(parts[1]),
			Name:    starcoin_types.Identifier(parts[2]),
		}}, nil
}

func (this *Submitter) ProcessEpochs(epochs []*msg.Tx) error {
	for _, m := range epochs {
		if m.Type() != msg.POLY_EPOCH || m.PolyEpoch == nil {
			return fmt.Errorf("Invalid Poly epoch message %s", m.Encode())
		}
		epoch := m.PolyEpoch
		log.Info("Submitting poly epoch", "epoch", epoch.EpochId, "height", epoch.Height, "chain", this.name, "current poly height ")

		log.Info("Print change epoch data: ",
			" \nepoch.Header: ", hex.EncodeToString(epoch.Header),
			"\nepoch.Seal: ", hex.EncodeToString(epoch.Seal))

		rawTx, err := this.ExecuteScriptFunction(
			starcoin_types.ModuleId{Address: this.wallet.Address, Name: "zion_cross_chain_manager_script"},
			"change_epoch",
			[]starcoin_types.TypeTag{},
			[][]byte{
				encode_u8vector_argument(epoch.Header),
				encode_u8vector_argument(epoch.Seal),
			})
		if err != nil {
			return fmt.Errorf("Starcoin epoch sync SubmitTransaction failed. epoch: %d, err: %v", epoch.EpochId, err)
		} else {
			log.Info("Starcoin epoch sync", "epoch", epoch.EpochId, "hash", rawTx)
		}
		count := 20
	CONFIRM:
		for {
			txInfo, e := this.sdk.Node().GetTransactionInfoByHash(this.Context, rawTx)
			if e != nil {
				count--
				e = fmt.Errorf("Starcoin epoch sync GetTransactionByHash failed, hash: %s, err: %v", rawTx, e)
			} else {
				if strings.EqualFold("\"Executed\"", string(txInfo.Status)) {
					log.Info("Starcoin epoch sync tx confirmed", "epoch", epoch.EpochId, "hash", rawTx)
					break CONFIRM
				} else {
					e = fmt.Errorf("Starcoin epoch sync tx pedding, hash: %s, VmStatus: %s", rawTx, txInfo.Status)
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

func ToUint64(i interface{}) (uint64, error) {
	switch i := i.(type) {
	case uint64:
		return i, nil
	case float64:
		return uint64(i), nil
	case string:
		return strconv.ParseUint(i, 10, 64)
	case json.Number:
		r, err := i.Int64()
		return uint64(r), err
	}
	return 0, fmt.Errorf("unknown type to uint64 %t", i)
}

func ExtractSingleResult(result interface{}) interface{} {
	r := result.([]interface{})
	if len(r) == 0 {
		return nil
	}
	return r[0]
}

func (this *Submitter) GetPolyEpochStartHeight() (uint64, error) {
	c := starcoin_client.ContractCall{
		FunctionId: fmt.Sprintf("%s::zion_cross_chain_manager::getCurEpochStartHeight", "0x"+strings.TrimPrefix(this.ccm, "0x")),
		TypeArgs:   []string{},
		Args:       []string{},
	}
	r, err := this.sdk.Node().CallContract(context.Background(), c)
	if err != nil {
		return 0, err
	}
	return ToUint64(ExtractSingleResult(r))
}

func (this *Submitter) Stop() error {
	this.wg.Wait()
	return nil
}
