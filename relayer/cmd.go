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

package relayer

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/urfave/cli/v2"

	"github.com/ethereum/go-ethereum/accounts/keystore"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/bridge"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/tools"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

const (
	SET_HEADER_HEIGHT    = "setheaderblock"
	SET_TX_HEIGHT        = "settxblock"
	RELAY_TX             = "submit"
	STATUS               = "status"
	HTTP                 = "http"
	PATCH                = "patch"
	SKIP                 = "skip"
	CHECK_SKIP           = "checkskip"
	CREATE_ACCOUNT       = "createaccount"
	UPDATE_ACCOUNT       = "updateaccount"
	ENCRYPT_FILE         = "encryptfile"
	DECRYPT_FILE         = "decryptfile"
	CHECK_WALLET         = "wallet"
	ADD_SIDECHAIN        = "addsidechain"
	SYNC_GENESIS         = "syncgenesis"
	CREATE_GENESIS       = "creategenesis"
	SIGN_POLY_TX         = "signpolytx"
	SEND_POLY_TX         = "sendpolytx"
	APPROVE_SIDECHAIN    = "approvesidechain"
	INIT_GENESIS         = "initgenesis"
	SYNC_HEADER          = "syncheader"
	GET_SIDE_CHAIN       = "getsidechain"
	SCAN_POLY_TX         = "scanpolytx"
	VALIDATE             = "validate"
	VALIDATE_BLOCK       = "validateblock"
	SET_VALIDATOR_HEIGHT = "setvalidatorblock"
	HTTP_SUBMIT          = "httpsubmit"
)

var _Handlers = map[string]func(*cli.Context) error{}

func init() {
	_Handlers[SET_HEADER_HEIGHT] = SetHeaderSyncHeight
	_Handlers[SET_TX_HEIGHT] = SetTxSyncHeight
	_Handlers[STATUS] = Status
	_Handlers[HTTP] = Http
	_Handlers[PATCH] = Patch
	_Handlers[SKIP] = Skip
	_Handlers[CHECK_SKIP] = CheckSkip
	_Handlers[RELAY_TX] = RelayTx
	_Handlers[CHECK_WALLET] = CheckWallet
	_Handlers[CREATE_ACCOUNT] = CreateAccount
	_Handlers[UPDATE_ACCOUNT] = UpdateAccount
	_Handlers[ENCRYPT_FILE] = EncryptFile
	_Handlers[DECRYPT_FILE] = DecryptFile
	_Handlers[ADD_SIDECHAIN] = AddSideChain
	_Handlers[SYNC_GENESIS] = SyncGenesis
	_Handlers[CREATE_GENESIS] = CreateGenesis
	_Handlers[SIGN_POLY_TX] = SignPolyTx
	_Handlers[SEND_POLY_TX] = SendPolyTx
	_Handlers[SYNC_HEADER] = SyncHeader
	_Handlers[APPROVE_SIDECHAIN] = ApproveSideChain
	_Handlers[INIT_GENESIS] = SyncContractGenesis
	_Handlers[GET_SIDE_CHAIN] = FetchSideChain
	_Handlers[SCAN_POLY_TX] = ScanPolyTxs
	_Handlers[VALIDATE] = Validate
	_Handlers[VALIDATE_BLOCK] = ValidateBlock
	_Handlers[SET_VALIDATOR_HEIGHT] = SetTxValidatorHeight
	_Handlers[HTTP_SUBMIT] = HttpSubmit
}

func CheckWallet(ctx *cli.Context) (err error) {
	chain := uint64(ctx.Int("chain"))
	for _, c := range base.ETH_CHAINS {
		if chain > 0 && c != chain {
			continue
		}
		fmt.Printf("Wallet status %s:\n", base.GetChainName(chain))
		_, err := ChainSubmitter(chain)
		if err != nil {
			log.Error("Failed to find the submitter", "chain", base.GetChainName(chain), "err", err)
		} else {
			// TODO: dump balance status of wallet accounts
		}
	}
	return nil
}

func RelayTx(ctx *cli.Context) (err error) {
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	hash := ctx.String("hash")
	free := ctx.Bool("free")
	sender := ctx.String("sender")
	params := &msg.Tx{
		SkipCheckFee: free,
		DstGasPrice:  ctx.String("price"),
		DstGasPriceX: ctx.String("pricex"),
		DstGasLimit:  uint64(ctx.Int("limit")),
	}
	if len(sender) > 0 {
		params.DstSender = sender
	}
	if ctx.Bool("auto") {
		params.SrcChainId = chain
		if chain == base.POLY {
			params.PolyHash = hash
		} else {
			params.SrcHash = hash
		}
		Relay(params)
		return
	}
	_, err = relayTx(height, chain, hash, free, params)
	return
}

func relayTx(height, chain uint64, hash string, free bool, params *msg.Tx) (txslog map[string]string, err error) {
	txslog = make(map[string]string)
	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	var listener IChainListener
	if chain == 0 {
		listener, err = PolyListener()
	} else {
		listener, err = ChainListener(chain, ps.SDK())
	}
	if err != nil {
		return
	}
	if height == 0 && hash != "" {
		height, err = listener.GetTxBlock(hash)
		if err != nil {
			log.Error("Failed to get tx block", "hash", hash)
			err = fmt.Errorf("Failed to get tx block hash", "hash", hash, "err", err.Error())
			return
		}
	}

	if height == 0 {
		log.Error("Failed to patch tx for height is invalid")
		err = fmt.Errorf("Failed to patch tx for height is invalid", "hash", hash)
		return
	}

	txs, err := listener.Scan(height)
	if err != nil {
		log.Error("Fetch block txs error", "height", height, "err", err)
		err = fmt.Errorf("Fetch block txs error", "height", height, "err", err)
		return
	}

	count := 0
	var bridge *bridge.SDK
	for _, tx := range txs {
		txHash := tx.SrcHash
		if chain == base.POLY {
			txHash = tx.PolyHash
		}
		if hash == "" || util.LowerHex(hash) == util.LowerHex(txHash) {
			txslog[txHash] += fmt.Sprintf("Found patch target tx hash: %v height: %v ", txHash, height)
			log.Info("Found patch target tx", "hash", txHash, "height", height)
			if chain == base.POLY {
				tx.CapturePatchParams(params)
				if !free {
					if bridge == nil {
						bridge, err = Bridge()
						if err != nil {
							txslog[txHash] += fmt.Sprintf("Failed to init bridge sdk. ")
							log.Error("Failed to init bridge sdk")
							continue
						}
					}
					res, err := CheckFee(bridge, tx)
					if err != nil {
						txslog[txHash] += fmt.Sprintf("Failed to call check fee ")
						log.Error("Failed to call check fee", "poly_hash", tx.PolyHash)
						continue
					}
					if res.Pass() {
						txslog[txHash] += fmt.Sprintf("Check fee pass ")
						log.Info("Check fee pass", "poly_hash", tx.PolyHash)
					} else {
						txslog[txHash] += fmt.Sprintf("Check fee failed ")
						log.Info("Check fee failed", "poly_hash", tx.PolyHash)
						fmt.Println(util.Verbose(tx))
						fmt.Println(res)
						continue
					}
				}
				sub, err := ChainSubmitter(tx.DstChainId)
				if err != nil {
					txslog[txHash] += fmt.Sprintf("Failed to init chain submitter, chain: %v, err: %v ", tx.DstChainId, err.Error())
					log.Error("Failed to init chain submitter", "chain", tx.DstChainId, "err", err)
					continue
				}
				err = sub.ProcessTx(tx, ps.ComposeTx)
				if err != nil {
					txslog[txHash] += fmt.Sprintf("Failed to process tx, chain: %v, err:%v ", tx.DstChainId, err.Error())
					log.Error("Failed to process tx", "chain", tx.DstChainId, "err", err)
					continue
				}
				if tx.DstHash == "" {
					txslog[txHash] += fmt.Sprintf("***Tx already imported to dstchain.*** ")
				}
				err = sub.SubmitTx(tx)
				txslog[txHash] += fmt.Sprintf("Submtter patching poly tx, chain: %v ", tx.DstChainId)
				if err != nil {
					txslog[txHash] += fmt.Sprintf("err: %v ", err.Error())
				}
				log.Info("Submtter patching poly tx", "hash", txHash, "chain", tx.DstChainId, "err", err)
			} else {
				err = ps.ProcessTx(tx, listener)
				txslog[txHash] += fmt.Sprintf("Submtter patching src tx, chain: %v ", tx.SrcChainId)
				if err != nil {
					txslog[txHash] += fmt.Sprintf("err: %v ", err.Error())
				}
				if tx.PolyHash == "" {
					txslog[txHash] += fmt.Sprintf("***Tx already imported to poly.*** ")
				}
				log.Info("Submtter patching src tx", "hash", txHash, "chain", tx.SrcChainId, "err", err)
			}
			fmt.Println(util.Verbose(tx))
			txslog[txHash] += fmt.Sprintf(util.Json(tx))
			count++
		} else {
			txslog[txHash] += fmt.Sprintf("Found tx in block not targeted, height: %v ", height)
			log.Info("Found tx in block not targeted", "hash", txHash, "height", height)
		}
	}
	log.Info("Patched txs per request", "count", count)
	return
}

type StatusHandler struct {
	redis *redis.Client
	poly  *poly.SDK
	store *bus.RedisChainStore
}

func NewStatusHandler(opt *redis.Options) *StatusHandler {
	client := bus.New(opt)
	sdk, err := poly.WithOptions(base.POLY, config.CONFIG.Poly.Nodes, time.Minute, 1)
	if err != nil {
		log.Error("Failed to initialize poly sdk")
		panic(err)
	}

	return &StatusHandler{redis: client, poly: sdk, store: bus.NewRedisChainStore(
		bus.ChainHeightKey{}, client, 0,
	)}
}

func (h *StatusHandler) Skip(hash string) (err error) {
	return bus.NewRedisSkipCheck(h.redis).Skip(context.Background(), &msg.Tx{PolyHash: hash})
}

func (h *StatusHandler) CheckSkip(hash string) (skip bool, err error) {
	return bus.NewRedisSkipCheck(h.redis).CheckSkip(context.Background(), &msg.Tx{PolyHash: hash})
}

func (h *StatusHandler) Height(chain uint64, key bus.ChainHeightType) (uint64, error) {
	h.store.Key = bus.ChainHeightKey{ChainId: chain, Type: key}
	return h.store.GetHeight(context.Background())
}

func (h *StatusHandler) SetHeight(chain uint64, key bus.ChainHeightType, height uint64) (err error) {
	h.store.Key = bus.ChainHeightKey{ChainId: chain, Type: key}
	return h.store.UpdateHeight(context.Background(), height)
}

func (h *StatusHandler) Len(chain uint64, ty msg.TxType) (uint64, error) {
	return bus.NewRedisTxBus(h.redis, chain, ty).Len(context.Background())
}

func (h *StatusHandler) LenDelayed() (uint64, error) {
	return bus.NewRedisDelayedTxBus(h.redis).Len(context.Background())
}

func (h *StatusHandler) LenSorted(chain uint64, ty msg.TxType) (uint64, error) {
	return bus.NewRedisSortedTxBus(h.redis, chain, ty).Len(context.Background())
}

func Status(ctx *cli.Context) (err error) {
	h := NewStatusHandler(config.CONFIG.Bus.Redis)
	targetChain := ctx.Uint64("chain")
	for _, chain := range base.CHAINS {
		if targetChain != 0 && targetChain != chain {
			continue
		}
		fmt.Printf("Status %s:\n", base.GetChainName(chain))

		latest, _ := h.Height(chain, bus.KEY_HEIGHT_CHAIN)
		sync, _ := h.Height(chain, bus.KEY_HEIGHT_CHAIN_HEADER)
		mark, _ := h.Height(chain, bus.KEY_HEIGHT_HEADER)
		tx, _ := h.Height(chain, bus.KEY_HEIGHT_TX)
		header := uint64(0)
		switch chain {
		case base.BSC, base.HECO, base.MATIC, base.ETH, base.O3, base.STARCOIN, base.BYTOM, base.HSC:
			header, _ = h.poly.Node().GetSideChainHeight(chain)
		default:
		}

		fmt.Printf("  Latest node height: %v\n", latest)
		fmt.Printf("  Latest sync height: %v\n", header)
		fmt.Printf("  Header sync height: %v\n", sync)
		fmt.Printf("  Header mark height: %v\n", mark)
		fmt.Printf("  tx listen height  : %v\n", tx)
		if latest > 0 {
			headerDiff := int64(latest) - int64(header)
			if headerDiff < 0 {
				headerDiff = 0
			}
			txDiff := int64(latest) - int64(tx)
			if txDiff < 0 {
				txDiff = 0
			}
			fmt.Printf("  header sync height diff: %v\n", headerDiff)
			fmt.Printf("  tx listen height diff  : %v\n", txDiff)
		}
		qSrc, _ := h.LenSorted(chain, msg.SRC)
		qPoly, _ := h.Len(chain, msg.POLY)
		fmt.Printf("  src tx queue size : %v\n", qSrc)
		fmt.Printf("  poly tx queue size: %v\n", qPoly)
	}
	qDelayed, _ := h.LenDelayed()
	fmt.Printf("Status shared:\n")
	fmt.Printf("  delayed tx queue size: %v\n", qDelayed)
	return nil
}

func SetHeaderSyncHeight(ctx *cli.Context) (err error) {
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	return NewStatusHandler(config.CONFIG.Bus.Redis).SetHeight(chain, bus.KEY_HEIGHT_HEADER_RESET, height)
}

func SetTxSyncHeight(ctx *cli.Context) (err error) {
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	return NewStatusHandler(config.CONFIG.Bus.Redis).SetHeight(chain, bus.KEY_HEIGHT_TX, height)
}

func SetTxValidatorHeight(ctx *cli.Context) (err error) {
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	return NewStatusHandler(config.CONFIG.Bus.Redis).SetHeight(chain, bus.KEY_HEIGHT_VALIDATOR, height)
}

func Skip(ctx *cli.Context) (err error) {
	hash := ctx.String("hash")
	return NewStatusHandler(config.CONFIG.Bus.Redis).Skip(hash)
}

func CheckSkip(ctx *cli.Context) (err error) {
	hash := ctx.String("hash")
	skip, err := NewStatusHandler(config.CONFIG.Bus.Redis).CheckSkip(hash)
	if skip {
		log.Info("Hash was marked to skip", "hash", hash)
	}
	return
}

func HandleCommand(method string, ctx *cli.Context) error {
	h, ok := _Handlers[method]
	if !ok {
		return fmt.Errorf("Unsupported subcommand %s", method)
	}
	return h(ctx)
}

func UpdateAccount(ctx *cli.Context) (err error) {
	path := ctx.String("path")
	pass, err := msg.ReadPassword("passphrase")
	if err != nil {
		return
	}
	newPass, err := msg.ReadPassword("new passphrase")
	if err != nil {
		return
	}
	password := string(pass)
	newPassword := string(newPass)
	if path == "" {
		log.Error("Wallet patch can not be empty")
		return
	}
	ks := keystore.NewKeyStore(path, keystore.StandardScryptN, keystore.StandardScryptP)
	for i, a := range ks.Accounts() {
		err = ks.Update(a, password, newPassword)
		log.Info("Updating passphrase", "index", i, "account", a.Address.String(), "newer", newPassword, "err", err)
		if err != nil {
			log.Fatal("Failed to update password")
		}
	}
	return
}

func CreateAccount(ctx *cli.Context) (err error) {
	path := ctx.String("path")
	if path == "" {
		log.Error("Wallet patch can not be empty")
		return
	}
	pass, err := msg.ReadPassword("passphrase")
	if err != nil {
		return
	}
	ks := keystore.NewKeyStore(path, keystore.StandardScryptN, keystore.StandardScryptP)
	account, err := ks.NewAccount(string(pass))
	if err != nil {
		return
	}
	log.Info("Created new account", "address", account.Address.Hex())
	/*
		data, err := ks.Export(account, password, password)
		if err != nil {
			return
		}
		fmt.Println(string(data))
		err = ioutil.WriteFile(fmt.Sprintf("%s/%s.json", path, account.Address.Hex()), data, 0644)
		if err != nil {
			log.Error("Failed to write account file", "err", err)
		}
	*/
	return nil
}

func ScanPolyTxs(ctx *cli.Context) (err error) {
	chain := ctx.Uint64("chain")
	start := ctx.Uint64("height")
	lis, err := PolyListener()
	if err != nil {
		return
	}
	sub, err := PolySubmitter()
	if err != nil {
		return
	}
	for {
		txs, err := lis.Scan(start)
		if err != nil {
			log.Error("Scan poly block failured", "err", err, "height", start)
			time.Sleep(time.Second)
			continue
		}
		log.Info("Scanned poly block", "size", len(txs), "block", start)
		for _, tx := range txs {
			if tx.SrcChainId != chain {
				continue
			}
			fmt.Println(util.Json(tx))
			for {
				value, _, _, e := sub.GetPolyParams(tx)
				if value != nil {
					log.Info("SRC", "ccid", hex.EncodeToString(value.MakeTxParam.CrossChainID), "to", value.MakeTxParam.ToChainID,
						"method", value.MakeTxParam.Method)
					break
				} else {
					log.Error("Fetc SRC failed", "err", e)
					time.Sleep(time.Second)
				}
			}
		}
		start++
	}
	return
}

func ValidateBlock(ctx *cli.Context) (err error) {
	return nil
}

func Validate(ctx *cli.Context) (err error) {
	return
}

func watchAlarms(outputs chan tools.CardEvent) {
	c := 0
	for o := range outputs {
		c++
		fmt.Printf("!!!!!!! Alarm(%v): %s \n", c, util.Json(o))
		if len(tools.DingUrl) == 0 {
			continue
		}
		err := tools.PostCardEvent(o)
		if err != nil {
			log.Error("Post dingtalk failure", "err", err)
		}
		handleAlarm(o)
		time.Sleep(time.Second)
	}
}

func handleAlarm(o tools.CardEvent) {
	switch o.(type) {
	case *msg.InvalidUnlockEvent, *msg.InvalidPolyCommitEvent:
	default:
		return
	}

	if len(config.CONFIG.Validators.PauseCommand) == 0 {
		return
	}
	go func() {
		cmd := exec.Command(config.CONFIG.Validators.PauseCommand[0], config.CONFIG.Validators.PauseCommand[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
		err := cmd.Run()
		if err != nil {
			log.Error("Run handle event command error %v %v", err, util.Json(o))
		}
	}()
	go Notify(fmt.Sprintf(config.CONFIG.Validators.DialTemplate, "Poly", "Invalid Unlock"))
}

func Notify(content string) {
	for _, target := range config.CONFIG.Validators.DialTargets {
		go Dial(target, content)
	}
}

func Dial(target, content string) error {
	v := url.Values{}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	h := md5.New()
	h.Write([]byte(config.CONFIG.Validators.HuyiAccount + config.CONFIG.Validators.HuyiPassword + target + content + now))
	v.Set("account", config.CONFIG.Validators.HuyiAccount)
	v.Set("password", hex.EncodeToString(h.Sum(nil)))
	v.Set("mobile", target)
	v.Set("content", content)
	v.Set("time", now)
	//body := ioutil.NopCloser(strings.NewReader(v.Encode())) //把form数据编下码
	body := strings.NewReader(v.Encode())
	client := &http.Client{}
	req, err := http.NewRequest("POST", config.CONFIG.Validators.HuyiUrl, body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	resp, err := client.Do(req)
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Info("Dail success", "to", target, "content", content, "data", string(data))
	return nil
}
