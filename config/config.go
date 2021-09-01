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
	Nodes             []string
	LockProxyContract []string
	CCMContract       string
	CCDContract       string
	Defer             int

	HeaderSync   *HeaderSyncConfig   // chain -> ch -> poly
	SrcTxSync    *SrcTxSyncConfig    // chain -> mq
	SrcTxCommit  *SrcTxCommitConfig  // mq -> poly
	PolyTxCommit *PolyTxCommitConfig // mq -> chain
}

func (c *ChainConfig) Init() (err error) {
	return
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
	Redis *redis.Options
}

type HeaderSyncConfig struct {
	ChainId uint64
	Batch   int
	Timeout int
	Buffer  int
	Enabled bool
}

type SrcTxSyncConfig struct {
	ListenerConfig `json:",inline"`
	Procs          int
	Enabled        bool
}

type SrcTxCommitConfig struct {
	ChainId uint64
	Procs   int
	Enabled bool
}

type PolyTxSyncConfig struct {
	SubmitterConfig `json:",inline"`
	Procs           int
	Enabled         bool
}

type PolyTxCommitConfig struct {
	ChainId uint64
	Procs   int
	Enabled bool
}

func (c *Config) Init() (err error) {
	if c.MetricHost == "" {
		c.MetricHost = "0.0.0.0"
	}
	if c.MetricPort == 0 {
		c.MetricPort = 6500
	}
	CONFIG = c
	return
}
