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
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
)

const (
	SET_HEADER_HEIGHT = "setheaderblock"
	SET_TX_HEIGHT     = "settxblock"
	RELAY_POLY_TX     = "submit"
	STATUS            = "status"
	METRIC            = "metric"
)

var _Handlers = map[string]func(*cli.Context) error{}

func init() {
	_Handlers[SET_HEADER_HEIGHT] = SetHeaderSyncHeight
	_Handlers[SET_TX_HEIGHT] = SetTxSyncHeight
	_Handlers[STATUS] = Status
	_Handlers[METRIC] = Metric
	_Handlers[RELAY_POLY_TX] = RelayPolyTx
}

func RelayPolyTx(ctx *cli.Context) (err error) {
	// height := uint64(ctx.Int("height"))
	hash := ctx.String("tx")
	if len(hash) == 0 {
		return fmt.Errorf("Invalid tx hash")
	}

	return
}

func Status(ctx *cli.Context) (err error) {
	redis := bus.New(config.CONFIG.Bus.Redis)
	getHeight := func(id uint64, key bus.ChainHeightType) (uint64, error) {
		return bus.NewRedisChainStore(
			bus.ChainHeightKey{ChainId: id, Type: key}, redis, 0,
		).GetHeight(context.Background())
	}
	for _, chain := range base.CHAINS {
		fmt.Printf("Status %s:\n", base.GetChainName(chain))
		h, err := getHeight(chain, bus.KEY_HEIGHT_HEADER)
		if err != nil {
			fmt.Printf("  Check header sync height error %v\n", err)
		} else {
			fmt.Printf("  Header sync Height %d\n", h)
		}
		h, err = getHeight(chain, bus.KEY_HEIGHT_TX)
		if err != nil {
			fmt.Printf("  Check tx sync height error %v\n", err)
		} else {
			fmt.Printf("  Tx sync Height %d\n", h)
		}
	}
	return nil
}

func SetHeaderSyncHeight(ctx *cli.Context) (err error) {
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	state := bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: chain, Type: bus.KEY_HEIGHT_HEADER_RESET}, bus.New(config.CONFIG.Bus.Redis), 0,
	)
	err = state.UpdateHeight(context.Background(), height)
	return
}

func SetTxSyncHeight(ctx *cli.Context) (err error) {
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	state := bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: chain, Type: bus.KEY_HEIGHT_TX}, bus.New(config.CONFIG.Bus.Redis), 0,
	)
	err = state.UpdateHeight(context.Background(), height)
	return
}

func HandleCommand(method string, ctx *cli.Context) error {
	h, ok := _Handlers[method]
	if !ok {
		return fmt.Errorf("Unsupported subcommand %s", method)
	}
	return h(ctx)
}
