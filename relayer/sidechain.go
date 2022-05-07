/*
 * Copyright (C) 2022 The poly network Authors
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
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ontio/ontology-crypto/sm2"
	"github.com/polynetwork/poly/core/types"
	"github.com/urfave/cli/v2"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ecom "github.com/ethereum/go-ethereum/common"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"
	poly_go_sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	"github.com/polynetwork/poly/native/service/governance/side_chain_manager"
	"github.com/polynetwork/poly/native/service/utils"

	"github.com/polynetwork/poly-relayer/config"
)

// For side chain registration
type ISideChain interface {
	GenesisHeader(uint64) ([]byte, error)
	SideChain() (*side_chain_manager.SideChain, error)
}

func GetSideChain(chainID uint64) ISideChain {
	return nil
}

func GetPolyWallets() (accounts []*poly_go_sdk.Account, err error) {
	err = filepath.Walk(config.CONFIG.Poly.ExtraWallets.Path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			log.Info("Loading wallet file", "path", path)
			c := *config.CONFIG.Poly.ExtraWallets
			c.Path = path
			account, err := wallet.NewPolySigner(&c)
			if err != nil {
				return err
			}
			accounts = append(accounts, account)
			return nil
		})
	return
}

func ApproveSideChain(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	update := ctx.Bool("update")
	ps, err := PolySubmitter()
	if err != nil {
		return
	}

	accounts, err := GetPolyWallets()
	if err != nil {
		return
	}
	for i, a := range accounts {
		var hash common.Uint256
		if update {
			hash, err = ps.SDK().Node().Native.Scm.ApproveUpdateSideChain(chainID, a)
		} else {
			hash, err = ps.SDK().Node().Native.Scm.ApproveRegisterSideChain(chainID, a)
		}
		if err != nil {
			panic(fmt.Errorf("No%d ApproveRegisterSideChain failed: %v", i, err))
		}
		log.Info("Confirming approve side chain", "chain", chainID,
			"index", i, "account", a.Address.ToHexString(), "hash", hash.ToHexString())
		height, err := ps.SDK().Node().Confirm(hash.ToHexString(), 1, 30)
		if err != nil {
			panic(fmt.Errorf("No%d ApproveRegisterSideChain failed: %v", i, err))
		}
		log.Info("Confirmed approve side chain", "chain", chainID, "height", height,
			"index", i, "account", a.Address.ToHexString(), "hash", hash.ToHexString())

	}
	return
}
func FetchSideChain(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	data, err := ps.SDK().Node().GetStorage(utils.SideChainManagerContractAddress.ToHexString(),
		append([]byte(side_chain_manager.SIDE_CHAIN), utils.GetUint64Bytes(chainID)...))
	if err != nil {
		return
	}
	if data == nil {
		log.Info("No such chain", "id", chainID)
	} else {
		chain := new(side_chain_manager.SideChain)
		err = chain.Deserialization(common.NewZeroCopySource(data))
		if err != nil {
			return
		}
		fmt.Println(util.Verbose(chain))
		fmt.Println("extra:", string(chain.ExtraInfo))
		fmt.Printf("ccm: %x\n", chain.CCMCAddress)
	}
	return
}

func AddSideChain(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	router := ctx.Uint64("router")
	ccm := ctx.String("ccm")
	isVoting := ctx.Bool("vote")
	update := ctx.Bool("update")

	var c *side_chain_manager.SideChain
	if !isVoting {
		sc := GetSideChain(chainID)
		c, err = sc.SideChain()
		if err != nil {
			return
		}
	} else {
		c = new(side_chain_manager.SideChain)
		c.Name = ctx.String("name")
		c.BlocksToWait = ctx.Uint64("blocks")
		c.ExtraInfo = []byte{}
		c.ChainId = chainID
		if c.ChainId == 0 || c.Name == "" {
			log.Error("Missing chainID or chain name")
			return
		}
	}
	if router > 0 {
		c.Router = router
	}
	if ccm != "" {
		c.CCMCAddress, err = common.HexToBytes(util.LowerHex(ccm))
		if err != nil {
			return
		}
	}
	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	accounts, err := GetPolyWallets()
	if err != nil {
		return
	}
	if len(accounts) == 0 {
		return fmt.Errorf("No valid poly wallet is provided")
	}
	account := accounts[0]
	var hash common.Uint256
	if update {
		hash, err = ps.SDK().Node().Native.Scm.UpdateSideChainExt(
			account.Address, chainID, c.Router, c.Name, c.BlocksToWait, c.CCMCAddress, c.ExtraInfo, account)
	} else {
		hash, err = ps.SDK().Node().Native.Scm.RegisterSideChainExt(
			account.Address, chainID, c.Router, c.Name, c.BlocksToWait, c.CCMCAddress, c.ExtraInfo, account)
	}
	if err != nil {
		return
	}
	height, err := ps.SDK().Node().Confirm(hash.ToHexString(), 1, 30)
	if err != nil {
		return
	}
	log.Info("Add side chain succeed", "height", height)
	return
}

func SyncHeader(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	height := ctx.Uint64("height")
	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	sc := GetSideChain(chainID)
	header, err := sc.GenesisHeader(height)
	if err != nil {
		return
	}
	hash, err := ps.SubmitHeaders(chainID, [][]byte{header})
	if err != nil {
		return
	}
	log.Info("Sync header succeed", "hash", hash)
	return
}

func SendPolyTx(ctx *cli.Context) (err error) {
	raw := ctx.String("tx")
	tx := &types.Transaction{}
	if raw == "" {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		raw = strings.TrimSpace(string(data))
	}
	data, err := hex.DecodeString(util.LowerHex(raw))
	if err != nil {
		log.Info("Failed to decode hex, will treat as file")
		body, err := ioutil.ReadFile(raw)
		if err != nil {
			return err
		}
		raw = strings.TrimSpace(string(body))
		data, err = hex.DecodeString(util.LowerHex(raw))
		if err != nil {
			return err
		}
	}
	if err := tx.Deserialization(common.NewZeroCopySource(data)); err != nil {
		return err
	}

	log.Info("MultiSigned tx", "progress", len(tx.Sigs[0].SigData), "required", tx.Sigs[0].M)
	if uint16(len(tx.Sigs[0].SigData)) < tx.Sigs[0].M {
		log.Error("Still missing signatures", "progress", len(tx.Sigs[0].SigData), "required", tx.Sigs[0].M)
		return fmt.Errorf("MultiSign lack, progress %v/%v", len(tx.Sigs[0].SigData), tx.Sigs[0].M)
	}

	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	log.Info("Sending poly tx to node...")
	hash, err := ps.SDK().Node().SendTransaction(tx)
	if err != nil {
		return
	}
	log.Info("Waiting poly tx to be confirmed")
	height, err := ps.SDK().Node().Confirm(hash.ToHexString(), 1, 30)
	if err != nil {
		return
	}
	log.Info("SendMultiSignTx succeed", "height", height)
	return
}

func SignPolyTx(ctx *cli.Context) (err error) {
	raw := ctx.String("tx")
	tx := &types.Transaction{}
	if raw == "" {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		raw = strings.TrimSpace(string(data))
	}
	data, err := hex.DecodeString(util.LowerHex(raw))
	if err != nil {
		log.Info("Failed to decode hex, will treat as file")
		body, err := ioutil.ReadFile(raw)
		if err != nil {
			return err
		}
		raw = strings.TrimSpace(string(body))
		data, err = hex.DecodeString(util.LowerHex(raw))
		if err != nil {
			return err
		}
	}
	if err := tx.Deserialization(common.NewZeroCopySource(data)); err != nil {
		return err
	}

	ps, err := PolySubmitter()
	if err != nil {
		return
	}

	accounts, err := GetPolyWallets()
	if err != nil {
		return
	}

	for i, acc := range accounts {
		err = ps.Poly().Node().MultiSignToTransaction(tx, tx.Sigs[0].M, tx.Sigs[0].PubKeys, acc)
		if err != nil {
			return fmt.Errorf("multi sign failed, err: %s", err)
		}
		log.Info("MultiSigned tx", "index", i, "account", acc.Address.ToHexString())
	}

	sink := common.NewZeroCopySink(nil)
	err = tx.Serialization(sink)
	if err != nil {
		return err
	}

	fmt.Printf("%x\n", sink.Bytes())
	log.Info("MultiSigned tx", "progress", len(tx.Sigs[0].SigData), "required", tx.Sigs[0].M)
	return
}

func CreateGenesis(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	height := ctx.Uint64("height")
	pubKeys := strings.Split(ctx.String("keys"), ",")
	sc := GetSideChain(chainID)
	header, err := sc.GenesisHeader(height)
	if err != nil {
		return
	}

	ps, err := PolySubmitter()
	if err != nil {
		return
	}

	tx, err := ps.SDK().Node().Native.Hs.NewSyncGenesisHeaderTransaction(chainID, header)
	if err != nil {
		return
	}

	keys := make([]keypair.PublicKey, len(pubKeys))
	for i, v := range pubKeys {
		pk, err := vconfig.Pubkey(v)
		if err != nil {
			return fmt.Errorf("failed to parse no%d pubkey: %v", i, err)
		}
		keys[i] = pk
	}

	tx.Sigs = append(tx.Sigs, types.Sig{
		SigData: make([][]byte, 0),
		M:       uint16(len(pubKeys) - (len(pubKeys)-1)/3),
		PubKeys: keys,
	})
	sink := common.NewZeroCopySink(nil)
	if err := tx.Serialization(sink); err != nil {
		return err
	}
	fmt.Printf("%x\n", sink.Bytes())
	log.Info("SyncGenesis raw tx created", "keys", ctx.String("keys"))
	return
}

func SyncGenesis(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	height := ctx.Uint64("height")
	sc := GetSideChain(chainID)
	header, err := sc.GenesisHeader(height)
	if err != nil {
		return
	}

	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	accounts, err := GetPolyWallets()
	if err != nil {
		return
	}
	hash, err := ps.SDK().Node().Native.Hs.SyncGenesisHeader(chainID, header, accounts)
	if err != nil {
		return
	}
	height, err = ps.SDK().Node().Confirm(hash.ToHexString(), 1, 30)
	if err != nil {
		return
	}
	log.Info("SyncGenesis succeed", "height", height)
	return
}

func SyncContractGenesis(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	ccm := ctx.String("ccm")
	height := ctx.Uint64("height")
	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	//NOTE: only block 0 can succeed?!
	/*
		if height == 0 {
			height, err = ps.SDK().Node().GetLatestHeight()
			if err != nil { return err }
		}
	*/
	block, err := ps.SDK().Node().GetBlockByHeight(uint32(height))
	if err != nil {
		return
	}
	info := &vconfig.VbftBlockInfo{}
	err = json.Unmarshal(block.Header.ConsensusPayload, info)
	if err != nil {
		panic(err)
	}
	if info.NewChainConfig == nil {
		height = uint64(info.LastConfigBlockNum)
		block, err := ps.SDK().Node().GetBlockByHeight(uint32(height))
		if err != nil {
			return err
		}
		info = &vconfig.VbftBlockInfo{}
		err = json.Unmarshal(block.Header.ConsensusPayload, info)
		if err != nil {
			panic(err)
		}
	}
	var bookkeepers []keypair.PublicKey
	for _, peer := range info.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)
	publickeys := make([]byte, 0)
	for _, key := range bookkeepers {
		publickeys = append(publickeys, GetOntNoCompressKey(key)...)
	}
	abi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return
	}
	data, err := abi.Pack("initGenesisBlock", block.Header.ToArray(), publickeys)
	if err != nil {
		return
	}
	sub, err := ChainSubmitter(chainID)
	if err != nil {
		return
	}
	hash, err := sub.(*eth.Submitter).Send(ecom.HexToAddress(ccm), big.NewInt(0), 0, nil, nil, data)
	if err != nil {
		return
	}
	log.Info("Send tx for initGenesisBlock", "chain", chainID, "hash", hash)
	return
}

func GetOntNoCompressKey(key keypair.PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == elliptic.P256().Params().Name {
				return ec.EncodePublicKey(t.PublicKey, false)
			}
			buf.WriteByte(byte(0x12))
		case ec.SM2:
			buf.WriteByte(byte(0x13))
		}
		label, err := GetCurveLabel(t.Curve.Params().Name)
		if err != nil {
			panic(err)
		}
		buf.WriteByte(label)
		buf.Write(ec.EncodePublicKey(t.PublicKey, false))
	default:
		panic("err")
	}
	return buf.Bytes()
}

func GetCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(elliptic.P224().Params().Name):
		return 1, nil
	case strings.ToUpper(elliptic.P256().Params().Name):
		return 2, nil
	case strings.ToUpper(elliptic.P384().Params().Name):
		return 3, nil
	case strings.ToUpper(elliptic.P521().Params().Name):
		return 4, nil
	case strings.ToUpper(sm2.SM2P256V1().Params().Name):
		return 20, nil
	case strings.ToUpper(btcec.S256().Name):
		return 5, nil
	default:
		panic("err")
	}
}
