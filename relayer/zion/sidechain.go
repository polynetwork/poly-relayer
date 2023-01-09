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

package zion

import (
	"fmt"
	"math/big"

	"github.com/devfans/zion-sdk/contracts/native/go_abi/side_chain_manager_abi"
	"github.com/devfans/zion-sdk/contracts/native/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
)

func (s *Submitter) RegisterSideChain(chainID uint64, router uint64, name string, ccmcAddress []byte, extraInfo []byte, update bool) (hash common.Hash, err error) {
	accounts := s.wallet.Accounts()
	if len(accounts) == 0 {
		err = fmt.Errorf("missing available account")
		return
	}
	method := "registerSideChain"
	if update {
		method = "updateSideChain"
		var chain *side_chain_manager_abi.ISideChainManagerSideChain
		chain, err = s.GetSideChain(chainID)
		if err != nil {
			return
		}
		if chain == nil {
			err = fmt.Errorf("side chain not found, id %d", chainID)
			return
		}
	}
	log.Info("Using account", "address", accounts[0].Address.String())
	data, err := zion.SM_ABI.Pack(method, chainID, router, name, ccmcAddress, extraInfo)
	if err != nil {
		return
	}
	hashStr, err := s.wallet.SendWithAccount(accounts[0], utils.SideChainManagerContractAddress, big.NewInt(0), 0, nil, nil, data)
	if err != nil {
		return
	}
	hash = common.HexToHash(hashStr)
	return
}

func (s *Submitter) ApproveRegisterSideChain(chainID uint64, update bool) (hash common.Hash, err error) {
	accounts := s.voter.Accounts()
	if len(accounts) == 0 {
		err = fmt.Errorf("missing available account")
		return
	}
	method := "approveRegisterSideChain"
	if update {
		method = "approveUpdateSideChain"
	}
	var hashStr string
	for i, account := range accounts {
		log.Info("Using account", "address", account.Address.String())
		var data []byte
		data, err = zion.SM_ABI.Pack(method, chainID)
		if err != nil {
			return
		}
		hashStr, err = s.voter.SendWithAccount(account, utils.SideChainManagerContractAddress, big.NewInt(0), 0, nil, nil, data)
		if err != nil {
			return
		}
		log.Info("Approved", "index", i, "account", account.Address.String(), "hash", hashStr)
	}
	hash = common.HexToHash(hashStr)
	return
}

func (s *Submitter) RegisterAsset(chainId uint64, assetMap, lockProxyMap map[uint64][]byte) (hash common.Hash, err error) {
	accounts := s.wallet.Accounts()
	if len(accounts) == 0 {
		err = fmt.Errorf("missing available account")
		return
	}
	method := "registerAsset"
	log.Info("Using account", "address", accounts[0].Address.String())

	assetMapKey := make([]uint64, len(assetMap))
	lockProxyMapKey := make([]uint64, len(lockProxyMap))
	assetMapValue := make([][]byte, len(assetMap))
	lockProxyMapValue := make([][]byte, len(lockProxyMap))
	for k, v := range assetMap {
		assetMapKey = append(assetMapKey, k)
		assetMapValue = append(assetMapValue, v)
	}
	for k, v := range lockProxyMap {
		lockProxyMapKey = append(lockProxyMapKey, k)
		lockProxyMapValue = append(lockProxyMapValue, v)
	}
	data, err := zion.SM_ABI.Pack(method, chainId, assetMapKey, assetMapValue, lockProxyMapKey, lockProxyMapValue)
	if err != nil {
		return
	}
	hashStr, err := s.wallet.SendWithAccount(accounts[0], utils.SideChainManagerContractAddress, big.NewInt(0), 0, nil, nil, data)
	if err != nil {
		return
	}
	hash = common.HexToHash(hashStr)
	return
}

func (s *Submitter) GetSideChain(chainID uint64) (chain *side_chain_manager_abi.ISideChainManagerSideChain, err error) {
	c, err := s.sdk.Node().GetSideChain(nil, chainID)
	if err != nil {
		return
	}
	chain = &c
	return
}
