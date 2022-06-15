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
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/bridge"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/poly-relayer/msg"
)

var (
	BIN_DIR = "."
)

func init() {
	dir := os.Getenv("RELAYER_BIN")
	if len(dir) == 0 {
		dir = "."
	}
	BIN_DIR, _ = filepath.Abs(dir)
}

func Bin(chainId uint64, hash string) (bin string, err error) {
	if chainId == base.POLY {
		listener, err := PolyListener()
		if err != nil {
			return "", err
		}
		height, err := listener.GetTxBlock(hash)
		if err != nil {
			return "", err
		}
		txs, err := listener.Scan(height)
		if err != nil {
			log.Error("Fetch block txs error", "height", height, "err", err)
			return "", err
		}

		for _, tx := range txs {
			if util.LowerHex(hash) == util.LowerHex(tx.PolyHash.Hex()) {
				log.Info("Found patch target tx", "hash", hash, "height", height)
				chainId = tx.DstChainId
			}
		}
	}

	switch chainId {
	case base.MATIC:
		bin = "relayer_matic"
	case base.PLT:
		bin = "relayer_plt"
	case base.ONT:
		bin = "relayer_ont"
	case base.OK:
		bin = "relayer_ok"
	default:
		bin = "relayer_main"
	}
	bin = path.Join(BIN_DIR, bin)
	return
}

func Relay(tx *msg.Tx) {
	chain := tx.SrcChainId
	hash := tx.SrcHash
	if len(tx.PolyHash) > 0 {
		hash = tx.PolyHash.Hex()
	}
	bin, err := Bin(chain, hash)
	if len(bin) == 0 {
		log.Error("Failed to find relayer bin", "chain", chain, "hash", hash, "err", err)
		return
	}
	config := os.Getenv("RELAYER_CONFIG")
	if len(config) == 0 {
		config = "config.json"
	}
	args := []string{
		"-config", config,
		"submit",
		"-hash", hash, "-chain", strconv.Itoa(int(chain)),
		"-price", tx.DstGasPrice, "-pricex", tx.DstGasPriceX, "-limit", strconv.Itoa(int(tx.DstGasLimit)),
	}
	if tx.SkipCheckFee {
		args = append(args, "-free")
	}
	if tx.DstSender != nil {
		args = append(args, "-sender", tx.DstSender.(string))
	}
	cmd := exec.Command(bin, args...)
	log.Info(fmt.Sprintf("Executing auto patch %v: %v", bin, args))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Start()
	done := make(chan bool)
	go func() {
		log.Error("Command executed", "err", cmd.Wait())
		close(done)
	}()
	select {
	case <-done:
		log.Info("Relay tx executed", "chain", chain, "hash", hash)
	case <-time.After(40 * time.Second):
		log.Error("Failed to relay tx for a timeout", "chain", chain, "hash", hash)
	}
	cmd.Process.Kill()
	return
}

func AutoPatch() (err error) {
	timer := time.NewTicker(2 * time.Minute)
	for range timer.C {
		log.Info("Auto patch ticking")
		txs := []*msg.Tx{}
		for i, tx := range txs {
			log.Info(fmt.Sprintf("Auto patching %d/%d", i, len(txs)))
			Relay(tx)
		}
	}
	return
}

func CheckFee(sdk *bridge.SDK, tx *msg.Tx) (res *bridge.CheckFeeRequest, err error) {
	state := map[string]*bridge.CheckFeeRequest{}
	state[tx.PolyHash.Hex()] = &bridge.CheckFeeRequest{
		ChainId:  tx.SrcChainId,
		TxId:     tx.TxId,
		PolyHash: tx.PolyHash.Hex(),
	}
	err = sdk.Node().CheckFee(state)
	if err != nil {
		return
	}
	if state[tx.PolyHash.Hex()] == nil {
		state[tx.PolyHash.Hex()] = new(bridge.CheckFeeRequest)
	}
	return state[tx.PolyHash.Hex()], nil
}
