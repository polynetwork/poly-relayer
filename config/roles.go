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

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/polynetwork/bridge-common/base"
)

type Role struct {
	TxVote     bool // Tx vote
	HeaderSync bool // header sync
	EpochSync  bool // epoch sync
	TxListen   bool // chain(src) -> mq
	TxCommit   bool // mq -> poly
	PolyListen bool // poly -> mq
	PolyCommit bool // mq -> chain(dst)
}

type Roles map[uint64]Role

func (c *Config) ReadRoles(path string) (err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Read roles file error %v", err)
	}
	roles := Roles{}
	err = json.Unmarshal(data, &roles)
	if err != nil {
		return fmt.Errorf("Parse roles file error %v", err)
	}
	c.ApplyRoles(roles)
	return
}

func (c *Config) ApplyRoles(roles Roles) {
	for id, role := range roles {
		c.chains[id] = true
		if id == base.POLY {
			if c.Poly == nil {
				c.Poly = new(PolyChainConfig)
			}
			if c.Poly.PolyTxSync == nil {
				c.Poly.PolyTxSync = new(PolyTxSyncConfig)
			}
			c.Poly.PolyTxSync.Enabled = role.PolyListen
		} else {
			chain, ok := c.Chains[id]
			if !ok {
				chain = new(ChainConfig)
				c.Chains[id] = chain
			}
			if chain.SrcTxSync == nil {
				chain.SrcTxSync = new(SrcTxSyncConfig)
			}
			if chain.SrcTxCommit == nil {
				chain.SrcTxCommit = new(SrcTxCommitConfig)
			}
			if chain.PolyTxCommit == nil {
				chain.PolyTxCommit = new(PolyTxCommitConfig)
			}
			if chain.HeaderSync == nil {
				chain.HeaderSync = new(HeaderSyncConfig)
			}
			if chain.EpochSync == nil {
				chain.EpochSync = new(EpochSyncConfig)
			}
			if chain.TxVote == nil {
				chain.TxVote = new(TxVoteConfig)
			}
			chain.SrcTxSync.Enabled = role.TxListen
			chain.SrcTxCommit.Enabled = role.TxCommit
			chain.PolyTxCommit.Enabled = role.PolyCommit
			chain.HeaderSync.Enabled = role.HeaderSync
			chain.EpochSync.Enabled = role.EpochSync
			chain.TxVote.Enabled = role.TxVote
		}
	}
}
