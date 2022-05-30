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
	"path/filepath"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/tools"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"

	"github.com/polynetwork/poly-relayer/msg"
)

var (
	CONFIG      *Config
	WALLET_PATH string
	CONFIG_PATH string
	ENCRYPTED   bool
	PLAIN       bool
)

type Config struct {
	Env    string
	Bus    *BusConfig
	Poly   *PolyChainConfig
	Chains map[uint64]*ChainConfig

	// Http
	Host string
	Port int

	ValidMethods []string
	validMethods map[string]bool
	chains       map[uint64]bool
	Bridge       []string

	Validators struct {
		Src          []uint64
		Dst          []uint64
		PauseCommand []string
		DialTargets  []string
		DialTemplate string
		DingUrl      string
		HuyiUrl      string
		HuyiAccount  string
		HuyiPassword string
	}
}

// Parse file path, if path is empty, use config file directory path
func GetConfigPath(path, file string) string {
	if strings.HasPrefix(file, "/") {
		return file
	}
	if path == "" {
		path = filepath.Dir(CONFIG_PATH)
	}
	return filepath.Join(path, file)
}

func New(path string) (config *Config, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Read config file error %v", err)
	}
	if ENCRYPTED {
		var passphrase []byte
		if PLAIN {
			passphrase, err = msg.ReadInput("passphrase")
		} else {
			passphrase, err = msg.ReadPassword("passphrase")
		}
		if err != nil { return nil, err }
		data = msg.Decrypt(data, passphrase)
	}
	config = &Config{chains: map[uint64]bool{}}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("Parse config file error %v", err)
	}
	if config.Env != base.ENV {
		util.Fatal("Config env(%s) and build env(%s) does not match!", config.Env, base.ENV)
	}

	methods := map[string]bool{}
	for _, m := range config.ValidMethods {
		methods[m] = true
	}

	if config.Chains == nil {
		config.Chains = map[uint64]*ChainConfig{}
	}
	config.validMethods = methods
	return
}

type PolyChainConfig struct {
	PolySubmitterConfig `json:",inline"`
	PolyTxSync          *PolyTxSyncConfig
	ExtraWallets        *wallet.Config
}

type ChainConfig struct {
	ChainId           uint64
	Nodes             []string
	ExtraNodes        []string
	LockProxyContract []string
	CCMContract       string
	CCDContract       string
	ListenCheck       int
	CheckFee          bool
	Defer             int
	Wallet            *wallet.Config
	SrcFilter         *FilterConfig
	DstFilter         *FilterConfig

	HeaderSync   *HeaderSyncConfig   // chain -> ch -> poly
	SrcTxSync    *SrcTxSyncConfig    // chain -> mq
	SrcTxCommit  *SrcTxCommitConfig  // mq -> poly
	PolyTxCommit *PolyTxCommitConfig // mq -> chain
}

type ListenerConfig struct {
	ChainId           uint64
	Nodes             []string
	ExtraNodes        []string
	LockProxyContract []string
	CCMContract       string
	CCDContract       string
	ListenCheck       int
	Bus               *BusConfig
	Defer             int
}

type PolySubmitterConfig struct {
	ChainId uint64
	Nodes   []string
	Procs   int
	Wallet  *wallet.Config
}

func (c *PolySubmitterConfig) Fill(o *PolySubmitterConfig) *PolySubmitterConfig {
	if o == nil {
		o = new(PolySubmitterConfig)
	}
	o.ChainId = base.POLY
	if len(o.Nodes) == 0 {
		o.Nodes = c.Nodes
	}
	if o.Wallet == nil {
		o.Wallet = c.Wallet
	} else {
		o.Wallet.Path = GetConfigPath(WALLET_PATH, o.Wallet.Path)
	}
	return o
}

type SubmitterConfig struct {
	ChainId     uint64
	Nodes       []string
	ExtraNodes  []string
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
	Redis                *redis.Options `json:"-"`
	HeightUpdateInterval uint64
	Config               *struct {
		Network    string
		Addr       string
		Username   string
		Password   string
		DB         int
		MaxRetries int
	}
}

func (c *BusConfig) Init() {
	c.Redis = new(redis.Options)
	if c.Config != nil {
		v, _ := json.Marshal(c.Config)
		json.Unmarshal(v, c.Redis)
	}
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
	Poly            *PolySubmitterConfig
}

type SrcTxCommitConfig struct {
	*ListenerConfig `json:",inline"`
	Procs           int
	Enabled         bool
	Bus             *BusConfig
	Poly            *PolySubmitterConfig
	Filter          *FilterConfig
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
	CheckFee         bool
	Bus              *BusConfig
	Filter           *FilterConfig
}

func (c *Config) Active(chain uint64) bool {
	return c.chains[chain]
}

func (c *Config) Init() (err error) {
	if c.Host == "" {
		c.Host = "0.0.0.0"
	}
	if c.Port == 0 {
		c.Port = 6500
	}
	if c.Bus != nil {
		c.Bus.Init()
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

	tools.DingUrl = c.Validators.DingUrl

	CONFIG = c
	return
}

func (c *Config) AllowMethod(method string) bool {
	return c.validMethods[method]
}

func (c *PolyChainConfig) Init(bus *BusConfig) (err error) {
	c.ChainId = base.POLY
	if c.PolyTxSync != nil {
		if c.PolyTxSync.ListenerConfig == nil {
			c.PolyTxSync.ListenerConfig = new(ListenerConfig)
		}
		c.PolyTxSync.ChainId = base.POLY
		if c.PolyTxSync.Bus == nil {
			c.PolyTxSync.Bus = bus
		}
		if len(c.PolyTxSync.Nodes) == 0 {
			c.PolyTxSync.Nodes = c.Nodes
		}
	}
	if c.Wallet != nil {
		c.Wallet.Path = GetConfigPath(WALLET_PATH, c.Wallet.Path)
	}
	if c.ExtraWallets != nil {
		c.ExtraWallets.Path = GetConfigPath(WALLET_PATH, c.ExtraWallets.Path)
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
		c.Wallet.Path = GetConfigPath(WALLET_PATH, c.Wallet.Path)
		for _, p := range c.Wallet.KeyStoreProviders {
			p.Path = GetConfigPath(WALLET_PATH, p.Path)
		}
	}

	if c.SrcFilter != nil {
		c.SrcFilter.Init()
	}
	if c.DstFilter != nil {
		c.DstFilter.Init()
	}

	if c.HeaderSync != nil {
		c.HeaderSync.ListenerConfig = c.FillListener(c.HeaderSync.ListenerConfig, bus)
		c.HeaderSync.ChainId = chain
		if c.HeaderSync.Bus == nil {
			c.HeaderSync.Bus = bus
		}
		c.HeaderSync.Poly = poly.PolySubmitterConfig.Fill(c.HeaderSync.Poly)
	}

	if c.SrcTxSync == nil {
		c.SrcTxSync = new(SrcTxSyncConfig)
	}
	c.SrcTxSync.ListenerConfig = c.FillListener(c.SrcTxSync.ListenerConfig, bus)
	c.SrcTxSync.ChainId = chain
	if c.SrcTxSync.Bus == nil {
		c.SrcTxSync.Bus = bus
	}
	c.SrcTxSync.ListenerConfig = c.FillListener(c.SrcTxSync.ListenerConfig, bus)
	c.SrcTxSync.Poly = poly.PolySubmitterConfig.Fill(c.SrcTxSync.Poly)

	if c.SrcTxCommit == nil {
		c.SrcTxCommit = new(SrcTxCommitConfig)
	}
	c.SrcTxCommit.ListenerConfig = c.FillListener(c.SrcTxCommit.ListenerConfig, bus)
	c.SrcTxCommit.ChainId = chain
	if c.SrcTxCommit.Bus == nil {
		c.SrcTxCommit.Bus = bus
	}
	c.SrcTxCommit.Poly = poly.PolySubmitterConfig.Fill(c.SrcTxCommit.Poly)
	if c.SrcTxCommit.Filter == nil {
		c.SrcTxCommit.Filter = c.SrcFilter
	}

	if c.PolyTxCommit == nil {
		c.PolyTxCommit = new(PolyTxCommitConfig)
	}
	c.PolyTxCommit.CheckFee = c.CheckFee
	c.PolyTxCommit.SubmitterConfig = c.FillSubmitter(c.PolyTxCommit.SubmitterConfig)
	c.PolyTxCommit.ChainId = chain
	c.PolyTxCommit.Poly = poly.PolySubmitterConfig.Fill(c.PolyTxCommit.Poly)
	if c.PolyTxCommit.Bus == nil {
		c.PolyTxCommit.Bus = bus
	}
	if c.PolyTxCommit.Filter == nil {
		c.PolyTxCommit.Filter = c.DstFilter
	}
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
	if len(o.ExtraNodes) == 0 {
		o.ExtraNodes = c.ExtraNodes
	}
	if o.Wallet == nil {
		o.Wallet = c.Wallet
	} else {
		o.Wallet.Path = GetConfigPath(WALLET_PATH, o.Wallet.Path)
		if len(o.Wallet.Nodes) == 0 {
			o.Wallet.Nodes = c.Wallet.Nodes
		}
		for _, p := range o.Wallet.KeyStoreProviders {
			p.Path = GetConfigPath(WALLET_PATH, p.Path)
		}
	}

	if o.CCMContract == "" {
		o.CCMContract = c.CCMContract
	}
	if o.CCDContract == "" {
		o.CCDContract = c.CCDContract
	}

	return o
}

func (c *ChainConfig) FillListener(o *ListenerConfig, bus *BusConfig) *ListenerConfig {
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
	if len(o.ExtraNodes) == 0 {
		o.ExtraNodes = c.ExtraNodes
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

	if o.Bus == nil {
		o.Bus = bus
	}

	return o
}
