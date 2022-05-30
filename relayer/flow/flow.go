package flow

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/onflow/cadence"
	jsoncdc "github.com/onflow/cadence/encoding/json"
	"github.com/onflow/cadence/runtime"
	flowsdk "github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go/crypto/hash"
	flowcrypto "github.com/onflow/flow-go/fvm/crypto"
	flowgo "github.com/onflow/flow-go/model/flow"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/flow"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	pcom "github.com/polynetwork/poly/common"
	"sync"
	"time"
)

type Submitter struct {
	context.Context
	wg                                    *sync.WaitGroup
	config                                *config.SubmitterConfig
	sdk                                   *flow.SDK
	name                                  string
	ccm                                   string
	verifySigAndExecuteTxToLockProxyScrip []byte
	polyId                                uint64
	wallet                                *wallet.FlowWallet
}

func (s *Submitter) Init(config *config.SubmitterConfig) (err error) {
	s.config = config
	s.sdk, err = flow.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	if err != nil {
		return
	}
	if config.Wallet != nil {
		sdk, e := flow.WithOptions(config.ChainId, config.Wallet.Nodes, time.Minute, 1)
		if e != nil {
			return e
		}
		w := wallet.NewFlowWallet(config.Wallet, sdk)
		err = w.Init()
		if err != nil {
			return err
		}
		s.wallet = w
	}

	s.ccm = util.LowerHex(config.CCMContract)
	s.verifySigAndExecuteTxToLockProxyScrip = []byte(fmt.Sprintf(wallet.VerifySigAndExecuteTxToLockProxyScripTemplate, config.CCMContract, config.CCMContract))
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

func (s *Submitter) run(wallet *wallet.FlowWallet, mq bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer) error {
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
				tsp := time.Now().Unix() + 60
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
				//bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx) })
			}
		} else {
			log.Info("Submitted poly tx", "poly_hash", tx.PolyHash, "chain", s.name, "dst_hash", tx.DstHash)
			// todo flow verify a successful submit
		}
	}
}

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, bus bus.TxBus, delay bus.DelayedTxBus, composer msg.PolyComposer) error {
	fmt.Printf("Submitter=%+v\n", s)
	s.Context = ctx
	s.wg = wg
	log.Info("Starting submitter worker", "index", 0, "total", 1, "account", s.wallet.Address, "chain", s.name)
	go s.run(s.wallet, bus, delay, composer)
	return nil
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
		return fmt.Errorf("%s message dst chain does not match %v", m.DstChainId)
	}

	err = compose(m)
	if err != nil {
		return
	}
	return s.processPolyTx(m)
}

func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	tag := string(flowgo.UserDomainTag[:])
	var hasher hash.Hasher
	hasher, err = flowcrypto.NewPrefixedHashing(flowcrypto.RuntimeToCryptoHashingAlgorithm(runtime.HashAlgorithmSHA2_256), tag)
	if err != nil {
		return fmt.Errorf("create SHA2_256 hasher error %s", err)
	}

	args := new(flow.Args)
	err = args.Deserialization(pcom.NewZeroCopySource(tx.MerkleValue.MakeTxParam.Args))
	if err != nil {
		return fmt.Errorf("txHash=%s deserialization MakeTxParam.Args failed. error=%s", tx.PolyHash, err)
	}

	resourceRoute := new(flow.ResourceRoute)
	err = resourceRoute.Deserialization(pcom.NewZeroCopySource(args.ToAddress))
	if err != nil {
		return fmt.Errorf("txHash=%s deserialization MakeTxParam.Args.ToAddress failed. error=%s", tx.PolyHash, err)
	}
	tx.ResourcePath = resourceRoute.Path

	sigInfo := new(poly.SigInfo)
	err = sigInfo.Deserialization(pcom.NewZeroCopySource(tx.SigStorage))
	if err != nil {
		return fmt.Errorf("txHash=%s deserialization sigStorage failed. error=%s", tx.PolyHash, err)
	}

	sigs, signers := make([][]byte, 0), make([][]byte, 0)
	for k, sig := range sigInfo.SigInfo {
		sigs = append(sigs, sig)
		addr, e := pcom.AddressFromBase58(k)
		if e != nil {
			return fmt.Errorf("txHash=%s get address from encoded base58 string(%s) failed. error=%s", tx.PolyHash, k, e)
		}

		h := hasher.ComputeHash(tx.Subject)
		pub, e := flow.RecoverPubkeyFromFlowSig(h[:], sig, addr)
		if e != nil {
			return fmt.Errorf("txHash=%s recover pubkey from flow sig failed. error=%s", tx.PolyHash, e)
		}
		signers = append(signers, pub)
	}
	tx.Sigs = sigs
	tx.Signers = signers
	return
}

func (s *Submitter) SubmitTx(tx *msg.Tx) (err error) {
	account, err := s.wallet.CreateServiceAccount()
	if err != nil {
		return fmt.Errorf("%w flow tx CreateServiceAccount error: %s", msg.ERR_TX_EXEC_FAILURE, err)
	}
	referenceBlockID, err := s.getReferenceBlockId()
	if err != nil {
		return fmt.Errorf("%w flow tx getReferenceBlockId error: %s", msg.ERR_TX_EXEC_FAILURE, err)
	}

	userReceiverPublicPath := cadence.Path{Domain: "public", Identifier: tx.ResourcePath}
	pathStr := cadence.String(tx.ResourcePath)
	sigs, signers := make([]cadence.Value, 0), make([]cadence.Value, 0)
	for _, sig := range tx.Sigs {
		sigs = append(sigs, cadence.String(hex.EncodeToString(sig)))
	}
	for _, signer := range tx.Signers {
		signers = append(signers, cadence.String(hex.EncodeToString(signer)))
	}
	toMerkleValue := cadence.String(hex.EncodeToString(tx.Subject))

	transaction := flowsdk.NewTransaction().
		SetScript(s.verifySigAndExecuteTxToLockProxyScrip).
		AddAuthorizer(account.ServiceAcctAddr).
		AddRawArgument(jsoncdc.MustEncode(userReceiverPublicPath)).
		AddRawArgument(jsoncdc.MustEncode(pathStr)).
		AddRawArgument(jsoncdc.MustEncode(cadence.NewArray(sigs))).
		AddRawArgument(jsoncdc.MustEncode(cadence.NewArray(signers))).
		AddRawArgument(jsoncdc.MustEncode(toMerkleValue)).
		SetProposalKey(account.ServiceAcctAddr, account.ServiceAcctKey.Index, account.ServiceAcctKey.SequenceNumber).
		SetReferenceBlockID(referenceBlockID).
		SetPayer(account.ServiceAcctAddr)
	err = transaction.SignEnvelope(account.ServiceAcctAddr, account.ServiceAcctKey.Index, account.ServiceSigner)
	if err != nil {
		return fmt.Errorf("%w flow tx SignEnvelope error: %s", msg.ERR_TX_EXEC_FAILURE, err)
	}

	ctx := context.Background()
	err = s.sdk.Node().SendTransaction(ctx, *transaction)
	if err != nil {
		return fmt.Errorf("%w flow tx SendTransaction error: %s", msg.ERR_TX_EXEC_FAILURE, err)
	}

	id := transaction.ID()
	tx.DstHash = id.Hex()
	s.waitForSeal(ctx, id)
	return
}

func (s *Submitter) waitForSeal(ctx context.Context, id flowsdk.Identifier) (result *flowsdk.TransactionResult, err error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	count := 0
	for {
		select {
		case <-ticker.C:
			count++
			if count > 300 {
				err = fmt.Errorf("%s wait for seal timeout", id.Hex())
				log.Warn("waitForSeal timeout", "dstHash", id.Hex())
				return
			}
			result, err = s.sdk.Node().GetTransactionResult(ctx, id)
			if err != nil {
				log.Error("GetTransactionResult", "error", err)
				continue
			}
			if result.Status != flowsdk.TransactionStatusSealed {
				continue
			}
			log.Info("Transaction sealed", "dstHash", id.Hex())
			return
		}
	}
}

func (s *Submitter) getReferenceBlockId() (id flowsdk.Identifier, err error) {
	block, err := s.sdk.Node().GetLatestBlock(context.Background(), true)
	if err != nil {
		return
	}
	id = block.ID
	return
}

func (s *Submitter) Stop() error {
	s.wg.Wait()
	return nil
}
