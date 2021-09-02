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

	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"
)

var CONFIG *Config

type Config struct {
	Env        string
	Bus        *BusConfig
	Poly       *PolyChainConfig
	Chains     map[uint64]*ChainConfig
	MetricHost string
	MetricPort int
}

func New(path string) (config *Config, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Read config file error %v", err)
	}
	config = &Config{}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("Parse config file error %v", err)
	}
	if config.Env != base.ENV {
		util.Fatal("Config env(%s) and build env(%s) does not match!", config.Env, base.ENV)
	}
	return
}

type PolyChainConfig struct {
	PolySubmitterConfig `json:",inline"`
	PolyTxSync          *PolyTxSyncConfig
}

type ChainConfig struct {
	ChainId           uint64
	Nodes             []string
	LockProxyContract []string
	CCMContract       string
	CCDContract       string
	ListenCheck       int
	Defer             int
	Wallet            *wallet.Config

	HeaderSync   *HeaderSyncConfig   // chain -> ch -> poly
	SrcTxSync    *SrcTxSyncConfig    // chain -> mq
	SrcTxCommit  *SrcTxCommitConfig  // mq -> poly
	PolyTxCommit *PolyTxCommitConfig // mq -> chain
}

type ListenerConfig struct {
	ChainId           uint64
	Nodes             []string
	LockProxyContract []string
	CCMContract       string
	CCDContract       string
	ListenCheck       int
	Defer             int
}

type PolySubmitterConfig struct {
	ChainId uint64
	Nodes   []string
	Procs   int
	Wallet  *wallet.PolySignerConfig
}

func (c *PolySubmitterConfig) Fill(o *PolySubmitterConfig) *PolySubmitterConfig {
	if o == nil {
		return c
	}
	o.ChainId = base.POLY
	if len(o.Nodes) == 0 {
		o.Nodes = c.Nodes
	}
	if o.Wallet == nil {
		o.Wallet = c.Wallet
	}
	return o
}

type SubmitterConfig struct {
	ChainId     uint64
	Nodes       []string
	CCMContract string
	CCDContract string
	Wallet      *wallet.Config
}

type WalletConfig struct {
	Nodes    []string
	KeyStore string
	KeyPwd   map[string]string
}

type BusConfig struct {
	Redis                *redis.Options
	HeightUpdateInterval uint64
}

type HeaderSyncConfig struct {
	Batch   int
	Timeout int
	Buffer  int
	Enabled bool
	Poly    *PolySubmitterConfig
	*ListenerConfig
	Bus *BusConfig
}

type SrcTxSyncConfig struct {
	*ListenerConfig `json:",inline"`
	Procs           int
	Enabled         bool
	Bus             *BusConfig
}

type SrcTxCommitConfig struct {
	*ListenerConfig `json:",inline"`
	Procs           int
	Enabled         bool
	Bus             *BusConfig
	Poly            *PolySubmitterConfig
}

type PolyTxSyncConfig struct {
	*ListenerConfig `json:",inline"`
	Procs           int
	Enabled         bool
	Bus             *BusConfig
}

type PolyTxCommitConfig struct {
	*SubmitterConfig `json:",inline"`
	Poly             *PolySubmitterConfig
	Procs            int
	Enabled          bool
	Bus              *BusConfig
}

func (c *Config) Init() (err error) {
	if c.MetricHost == "" {
		c.MetricHost = "0.0.0.0"
	}
	if c.MetricPort == 0 {
		c.MetricPort = 6500
	}
	if c.Poly != nil {
		err = c.Poly.Init(c.Bus)
		if err != nil {
			return
		}
	}

	for chain, conf := range c.Chains {
		err = conf.Init(chain, c.Bus, c.Poly)
		if err != nil {
			return
		}
	}

	CONFIG = c
	return
}

func (c *PolyChainConfig) Init(bus *BusConfig) (err error) {
	c.ChainId = base.POLY
	if c.PolyTxSync != nil {
		c.PolyTxSync.ChainId = base.POLY
		if c.PolyTxSync.Bus == nil {
			c.PolyTxSync.Bus = bus
		}
		if len(c.PolyTxSync.Nodes) == 0 {
			c.PolyTxSync.Nodes = c.Nodes
		}
	}
	return
}

func (c *ChainConfig) Init(chain uint64, bus *BusConfig, poly *PolyChainConfig) (err error) {
	if c.ChainId != 0 && c.ChainId != chain {
		err = fmt.Errorf("Conflict chain id in config %d <> %d", c.ChainId, chain)
		return
	}
	c.ChainId = chain
	if c.Wallet != nil {
		if len(c.Wallet.Nodes) == 0 {
			c.Wallet.Nodes = c.Nodes
		}
	}

	if c.HeaderSync != nil {
		c.HeaderSync.ChainId = chain
		if c.HeaderSync.Bus == nil {
			c.HeaderSync.Bus = bus
		}
		c.HeaderSync.Poly = poly.PolySubmitterConfig.Fill(c.HeaderSync.Poly)
		c.HeaderSync.ListenerConfig = c.FillListener(c.HeaderSync.ListenerConfig)
	}

	if c.SrcTxSync != nil {
		c.SrcTxSync.ChainId = chain
		if c.SrcTxSync.Bus == nil {
			c.SrcTxSync.Bus = bus
		}
		c.SrcTxSync.ListenerConfig = c.FillListener(c.SrcTxSync.ListenerConfig)
	}

	if c.SrcTxCommit != nil {
		c.SrcTxCommit.ChainId = chain
		if c.SrcTxCommit.Bus == nil {
			c.SrcTxCommit.Bus = bus
		}
		c.SrcTxCommit.Poly = poly.PolySubmitterConfig.Fill(c.SrcTxCommit.Poly)
		c.SrcTxCommit.ListenerConfig = c.FillListener(c.SrcTxCommit.ListenerConfig)
	}

	if c.PolyTxCommit != nil {
		c.SrcTxCommit.ChainId = chain
		c.PolyTxCommit.Poly = poly.PolySubmitterConfig.Fill(c.PolyTxCommit.Poly)
	}
	c.PolyTxCommit.SubmitterConfig = c.FillSubmitter(c.PolyTxCommit.SubmitterConfig)
	return
}

func (c *ChainConfig) FillSubmitter(o *SubmitterConfig) *SubmitterConfig {
	if o == nil {
		o = new(SubmitterConfig)
	}
	if o.ChainId != 0 && c.ChainId != o.ChainId {
		util.Fatal("Conflict chain id in config for submitters %d <> %d", o.ChainId, c.ChainId)
	}
	o.ChainId = c.ChainId
	if len(o.Nodes) == 0 {
		o.Nodes = c.Nodes
	}
	if o.Wallet == nil {
		o.Wallet = c.Wallet
	} else if len(o.Wallet.Nodes) == 0 {
		o.Wallet.Nodes = c.Wallet.Nodes
	}

	if o.CCMContract == "" {
		o.CCMContract = c.CCMContract
	}
	if o.CCDContract == "" {
		o.CCDContract = c.CCDContract
	}

	return o
}

func (c *ChainConfig) FillListener(o *ListenerConfig) *ListenerConfig {
	if o == nil {
		o = new(ListenerConfig)
	}
	if o.ChainId != 0 && c.ChainId != o.ChainId {
		util.Fatal("Conflict chain id in config for listeners %d <> %d", o.ChainId, c.ChainId)
	}
	o.ChainId = c.ChainId
	if len(o.Nodes) == 0 {
		o.Nodes = c.Nodes
	}
	if o.Defer == 0 {
		o.Defer = c.Defer
	}
	if o.CCMContract == "" {
		o.CCMContract = c.CCMContract
	}
	if o.CCDContract == "" {
		o.CCDContract = c.CCDContract
	}
	if len(o.LockProxyContract) == 0 {
		o.LockProxyContract = c.LockProxyContract
	}

	if o.ListenCheck == 0 {
		o.ListenCheck = c.ListenCheck
	}

	return o
}
