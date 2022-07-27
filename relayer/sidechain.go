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
	"context"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/polynetwork/bridge-common/abi/eccm_abi"
	"math/big"
	"strings"

	"github.com/devfans/zion-sdk/contracts/native/go_abi/side_chain_manager_abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/urfave/cli/v2"
)

func FetchSideChain(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	chain, err := ps.GetSideChain(chainID)
	if err != nil {
		return
	}
	if chain == nil {
		log.Info("No such chain", "id", chainID)
	} else {
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

	if chainID == 0 {
		err = fmt.Errorf("side chain ID missing")
		return
	}

	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	var chain *side_chain_manager_abi.ISideChainManagerSideChain
	if update {
		chain, err = ps.GetSideChain(chainID)
		if err != nil {
			return
		}
		if chain == nil {
			return fmt.Errorf("side chain not found")
		}
	} else if !isVoting && router == 0 {
		err = fmt.Errorf("missing router")
		return
	} else {
		chain = new(side_chain_manager_abi.ISideChainManagerSideChain)
	}
	chain.Name = ctx.String("name")
	chain.BlocksToWait = ctx.Uint64("blocks")
	chain.ExtraInfo = []byte{}
	chain.ChainID = chainID
	chain.Router = ctx.Uint64("router")
	if chain.Name == "" {
		log.Error("Missing chainID or chain name")
		return
	}

	if ccm != "" {
		chain.CCMCAddress, err = hex.DecodeString(util.LowerHex(ccm))
		if err != nil {
			return
		}
	}

	hash, err := ps.RegisterSideChain(chain.ChainID, chain.Router, chain.Name, chain.BlocksToWait, chain.CCMCAddress, chain.ExtraInfo, update)
	log.Info("Sent tx", "hash", hash, "err", err)
	return
}

func ApproveSideChain(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	update := ctx.Bool("update")
	ps, err := PolySubmitter()
	if err != nil {
		return
	}

	_, err = ps.ApproveRegisterSideChain(chainID, update)
	return
}

func SyncContractGenesis(ctx *cli.Context) (err error) {
	chainID := ctx.Uint64("chain")
	ccm := ctx.String("ccm")
	sync := ctx.Bool("sync")
	ps, err := PolySubmitter()
	if err != nil {
		return
	}

	epoch, err := ps.SDK().Node().GetEpochInfo(0)
	if err != nil {
		return
	}
	if epoch == nil {
		return fmt.Errorf("epoch not found in zion?")
	}

	sub, err := ChainSubmitter(chainID)
	if err != nil {
		return
	}
	lis, err := PolyListener()
	if err != nil {
		return
	}

	height, err := sub.GetPolyEpochStartHeight(0)
	if err != nil {
		return
	}
	if height == 0 {
		info, err := lis.EpochById(epoch.ID.Uint64())
		if err != nil {
			return err
		}

		eccmAbi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerImplementationABI))
		if err != nil {
			return err
		}

		data, err := eccmAbi.Pack("initGenesisBlock", info.Header)
		if err != nil {
			return err
		}
		log.Info("info.Header", "", common.Bytes2Hex(info.Header))

		hash, err := sub.(*eth.Submitter).Send(common.HexToAddress(ccm), big.NewInt(0), 0, nil, nil, data)
		if err != nil {
			log.Error("Send", "err", err)
			return err
		}
		log.Info("Send tx for initGenesisBlock", "chain", chainID, "hash", hash)
	} else if sync {
		epochs, err := lis.EpochUpdate(context.Background(), height)
		if err != nil {
			return err
		}

		txs := []*msg.Tx{}
		for _, epoch := range epochs {
			txs = append(txs, &msg.Tx{
				TxType:     msg.POLY_EPOCH,
				PolyEpoch:  epoch,
				DstChainId: chainID,
			})
		}
		err = sub.ProcessEpochs(txs)
		if err != nil {
			return err
		}
	}
	return
}
