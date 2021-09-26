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

	"github.com/go-redis/redis/v8"
	"github.com/urfave/cli/v2"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
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

type StatusHandler struct {
	redis *redis.Client
}

func NewStatusHandler(config *redis.Options) *StatusHandler {
	return &StatusHandler{redis: bus.New(config)}
}

func (h *StatusHandler) Height(chain uint64, key bus.ChainHeightType) (uint64, error) {
	return bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: chain, Type: key}, h.redis, 0,
	).GetHeight(context.Background())
}

func (h *StatusHandler) SetHeight(chain uint64, key bus.ChainHeightType, height uint64) (err error) {
	return bus.NewRedisChainStore(
		bus.ChainHeightKey{ChainId: chain, Type: key}, h.redis, 0,
	).UpdateHeight(context.Background(), height)
}

func (h *StatusHandler) Len(chain uint64, ty msg.TxType) (uint64, error) {
	return bus.NewRedisTxBus(h.redis, chain, ty).Len(context.Background())
}

func Status(ctx *cli.Context) (err error) {
	h := NewStatusHandler(config.CONFIG.Bus.Redis)
	for _, chain := range base.CHAINS {
		fmt.Printf("Status %s:\n", base.GetChainName(chain))

		latest, _ := h.Height(chain, bus.KEY_HEIGHT_CHAIN)
		header, _ := h.Height(chain, bus.KEY_HEIGHT_HEADER)
		tx, _ := h.Height(chain, bus.KEY_HEIGHT_TX)

		fmt.Printf("  Latest node height: %v\n", latest)
		fmt.Printf("  Header sync height: %v\n", header)
		fmt.Printf("  tx listen height  : %v\n", tx)
		if latest > 0 {
			fmt.Printf("  header sync height diff: %v\n", latest-header)
			fmt.Printf("  tx listen height diff  : %v\n", latest-tx)
		}
		qSrc, _ := h.Len(chain, msg.SRC)
		qPoly, _ := h.Len(chain, msg.POLY)
		fmt.Printf("  src tx queue size : %v\n", qSrc)
		fmt.Printf("  poly tx queue size: %v\n", qPoly)
	}
	return nil
}

func SetHeaderSyncHeight(ctx *cli.Context) (err error) {
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	return NewStatusHandler(config.CONFIG.Bus.Redis).SetHeight(chain, bus.KEY_HEIGHT_HEADER_RESET, height)
}

func SetTxSyncHeight(ctx *cli.Context) (err error) {
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	return NewStatusHandler(config.CONFIG.Bus.Redis).SetHeight(chain, bus.KEY_HEIGHT_TX, height)
}

func HandleCommand(method string, ctx *cli.Context) error {
	h, ok := _Handlers[method]
	if !ok {
		return fmt.Errorf("Unsupported subcommand %s", method)
	}
	return h(ctx)
}
