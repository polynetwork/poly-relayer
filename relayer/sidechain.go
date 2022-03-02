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
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ontio/ontology-crypto/sm2"
	"github.com/urfave/cli/v2"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ecom "github.com/ethereum/go-ethereum/common"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/wallet"
	poly_go_sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	"github.com/polynetwork/poly/native/service/governance/side_chain_manager"

	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer/harmony"
)

// For side chain registration
type ISideChain interface {
	GenesisHeader(uint64) ([]byte, error)
	SideChain() (*side_chain_manager.SideChain, error)
}

func GetSideChain(chainID uint64) ISideChain {
	switch chainID {
	case base.HARMONY:
		listener, err :=  ChainListener(base.HARMONY, nil)
		if err != nil { panic(err) }
		return listener.(*harmony.Listener)
	}
	return nil
}

func GetPolyWallets() (accounts []*poly_go_sdk.Account, err error) {
	err = filepath.Walk(config.CONFIG.Poly.ExtraWallets.Path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() { return nil }
			log.Info("Loading wallet file", "path", path)
			c := *config.CONFIG.Poly.ExtraWallets
			c.Path = path
			account, err := wallet.NewPolySigner(&c)
			if err != nil { return err }
			accounts = append(accounts, account)
			return nil
		})
	return
}

func ApproveSideChain(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	ps, err := PolySubmitter()
	if err != nil {
		return
	}

	accounts, err := GetPolyWallets()
	if err != nil { return }
	for i, a := range accounts {
		hash, err := ps.SDK().Node().Native.Scm.ApproveRegisterSideChain(chainID, a)
		if err != nil {
			panic(fmt.Errorf("No%d ApproveRegisterSideChain failed: %v", i, err))
		}
		log.Info("Confirming approve side chain", "chain", chainID,
			"index", i, "account", a.Address.ToHexString(), "hash", hash.ToHexString())
		height, err := ps.SDK().Node().Confirm(hash.ToHexString(), 1, 0)
		if err != nil {
			panic(fmt.Errorf("No%d ApproveRegisterSideChain failed: %v", i, err))
		}
		log.Info("Confirmed approve side chain", "chain", chainID,"height", height,
			"index", i, "account", a.Address.ToHexString(), "hash", hash.ToHexString())

	}
	return
}

func AddSideChain(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	router := ctx.Uint64("router")
	ccm := ctx.String("ccm")

	sc := GetSideChain(chainID)
	c, err := sc.SideChain()
	if err != nil { return }
	if router > 0 {
		c.Router = router
	}
	if ccm != "" {
		c.CCMCAddress, err = common.HexToBytes(ccm)
		if err != nil { return }
	}
	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	accounts, err := GetPolyWallets()
	if err != nil { return }
	if len(accounts) == 0 {
		return fmt.Errorf("No valid poly wallet is provided")
	}
	account := accounts[0]
	hash, err := ps.SDK().Node().Native.Scm.RegisterSideChainExt(
		account.Address, chainID, c.Router, c.Name, c.BlocksToWait, c.CCMCAddress, c.ExtraInfo, account)
	if err != nil { return }
	height, err := ps.SDK().Node().Confirm(hash.ToHexString(), 1, 0)
	if err != nil { return }
	log.Info("Add side chain succeed", "height", height)
	return
}

func SyncGenesis(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	height := ctx.Uint64("height")
	sc := GetSideChain(chainID)
	header, err := sc.GenesisHeader(height)
	if err != nil { return }

	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	accounts, err := GetPolyWallets()
	if err != nil { return }
	hash, err := ps.SDK().Node().Native.Hs.SyncGenesisHeader(chainID, header, accounts)
	if err != nil { return }
	height, err = ps.SDK().Node().Confirm(hash.ToHexString(), 1, 0)
	if err != nil { return }
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
	if err != nil { return }
	info := &vconfig.VbftBlockInfo{}
	err = json.Unmarshal(block.Header.ConsensusPayload, info);
	if err != nil {
		panic(err)
	}
	if info.NewChainConfig == nil {
		height = uint64(info.LastConfigBlockNum)
		block, err := ps.SDK().Node().GetBlockByHeight(uint32(height))
		if err != nil { return err }
		info = &vconfig.VbftBlockInfo{}
		err = json.Unmarshal(block.Header.ConsensusPayload, info);
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
	if err != nil { return }
	data, err := abi.Pack("initGenesisBlock", block.Header.ToArray(), publickeys)
	if err != nil { return }
	sub, err := ChainSubmitter(chainID)
	if err != nil { return }
	hash, err := sub.(*eth.Submitter).Send(ecom.HexToAddress(ccm), big.NewInt(0), 0, nil, nil, data)
	if err != nil { return }
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

