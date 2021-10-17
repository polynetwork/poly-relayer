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
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/urfave/cli/v2"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

const (
	SET_HEADER_HEIGHT = "setheaderblock"
	SET_TX_HEIGHT     = "settxblock"
	RELAY_TX          = "submit"
	STATUS            = "status"
	HTTP              = "http"
	PATCH             = "patch"
	SKIP              = "skip"
	CHECK_SKIP        = "checkskip"
)

var _Handlers = map[string]func(*cli.Context) error{}

func init() {
	_Handlers[SET_HEADER_HEIGHT] = SetHeaderSyncHeight
	_Handlers[SET_TX_HEIGHT] = SetTxSyncHeight
	_Handlers[STATUS] = Status
	_Handlers[HTTP] = Http
	_Handlers[PATCH] = Patch
	_Handlers[SKIP] = Skip
	_Handlers[CHECK_SKIP] = CheckSkip
	_Handlers[RELAY_TX] = RelayTx
}

func RelayTx(ctx *cli.Context) (err error) {
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	hash := ctx.String("hash")
	params := &msg.Tx{
		SkipCheckFee: ctx.Bool("free"),
		DstGasPrice:  ctx.String("price"),
		DstGasPriceX: ctx.String("pricex"),
		DstGasLimit:  uint64(ctx.Int("limit")),
	}

	ps, err := PolySubmitter()
	if err != nil {
		return
	}
	var listener IChainListener
	if chain == 0 {
		listener, err = PolyListener()
	} else {
		listener, err = ChainListener(chain, ps.SDK())
	}
	if err != nil {
		return
	}
	if height == 0 && hash != "" {
		height, err = listener.GetTxBlock(hash)
		if err != nil {
			log.Error("Failed to get tx block", "hash", hash)
			return
		}
	}

	if height == 0 {
		log.Error("Failed to patch tx for height is invalid")
		return
	}

	txs, err := listener.Scan(height)
	if err != nil {
		log.Error("Fetch block txs error", "height", height, "err", err)
	}

	count := 0
	for _, tx := range txs {
		txHash := tx.SrcHash
		if chain == base.POLY {
			txHash = tx.PolyHash
		}
		if hash == "" || hash == txHash {
			log.Info("Found patch target tx", "hash", txHash, "height", height)
			if chain == base.POLY {
				tx.CapturePatchParams(params)
				sub, err := ChainSubmitter(tx.DstChainId)
				if err != nil {
					log.Error("Failed to init chain submitter", "chain", tx.DstChainId, "err", err)
					continue
				}
				err = sub.ProcessTx(tx, ps.ComposeTx)
				log.Info("Submtter patching poly tx", "hash", txHash, "chain", tx.DstChainId, "err", err)
			} else {
				err = ps.ProcessTx(tx, listener.Compose)
				log.Info("Submtter patching src tx", "hash", txHash, "chain", tx.SrcChainId, "err", err)
			}
			count++
		} else {
			log.Info("Found tx in block not targeted", "hash", txHash, "height", height)
		}
	}
	log.Info("Patched txs per request", "count", count)
	return
}

type StatusHandler struct {
	redis *redis.Client
	poly  *poly.SDK
	store *bus.RedisChainStore
}

func NewStatusHandler(opt *redis.Options) *StatusHandler {
	client := bus.New(opt)
	sdk, err := poly.WithOptions(base.POLY, config.CONFIG.Poly.Nodes, time.Minute, 1)
	if err != nil {
		log.Error("Failed to initialize poly sdk")
		panic(err)
	}

	return &StatusHandler{redis: client, poly: sdk, store: bus.NewRedisChainStore(
		bus.ChainHeightKey{}, client, 0,
	)}
}

func (h *StatusHandler) Skip(hash string) (err error) {
	return bus.NewRedisSkipCheck(h.redis).Skip(context.Background(), &msg.Tx{PolyHash: hash})
}

func (h *StatusHandler) CheckSkip(hash string) (skip bool, err error) {
	return bus.NewRedisSkipCheck(h.redis).CheckSkip(context.Background(), &msg.Tx{PolyHash: hash})
}

func (h *StatusHandler) Height(chain uint64, key bus.ChainHeightType) (uint64, error) {
	h.store.Key = bus.ChainHeightKey{ChainId: chain, Type: key}
	return h.store.GetHeight(context.Background())
}

func (h *StatusHandler) SetHeight(chain uint64, key bus.ChainHeightType, height uint64) (err error) {
	h.store.Key = bus.ChainHeightKey{ChainId: chain, Type: key}
	return h.store.UpdateHeight(context.Background(), height)
}

func (h *StatusHandler) Len(chain uint64, ty msg.TxType) (uint64, error) {
	return bus.NewRedisTxBus(h.redis, chain, ty).Len(context.Background())
}

func (h *StatusHandler) LenDelayed() (uint64, error) {
	return bus.NewRedisDelayedTxBus(h.redis).Len(context.Background())
}

func (h *StatusHandler) LenSorted(chain uint64, ty msg.TxType) (uint64, error) {
	return bus.NewRedisSortedTxBus(h.redis, chain, ty).Len(context.Background())
}

func Status(ctx *cli.Context) (err error) {
	h := NewStatusHandler(config.CONFIG.Bus.Redis)
	for _, chain := range base.CHAINS {
		fmt.Printf("Status %s:\n", base.GetChainName(chain))

		latest, _ := h.Height(chain, bus.KEY_HEIGHT_CHAIN)
		sync, _ := h.Height(chain, bus.KEY_HEIGHT_CHAIN_HEADER)
		mark, _ := h.Height(chain, bus.KEY_HEIGHT_HEADER)
		tx, _ := h.Height(chain, bus.KEY_HEIGHT_TX)
		header := uint64(0)
		switch chain {
		case base.BSC, base.HECO, base.MATIC, base.ETH, base.O3:
			header, _ = h.poly.Node().GetSideChainHeight(chain)
		default:
		}

		fmt.Printf("  Latest node height: %v\n", latest)
		fmt.Printf("  Latest sync height: %v\n", header)
		fmt.Printf("  Header sync height: %v\n", sync)
		fmt.Printf("  Header mark height: %v\n", mark)
		fmt.Printf("  tx listen height  : %v\n", tx)
		if latest > 0 {
			headerDiff := int64(latest) - int64(header)
			if headerDiff < 0 {
				headerDiff = 0
			}
			txDiff := int64(latest) - int64(tx)
			if txDiff < 0 {
				txDiff = 0
			}
			fmt.Printf("  header sync height diff: %v\n", headerDiff)
			fmt.Printf("  tx listen height diff  : %v\n", txDiff)
		}
		qSrc, _ := h.LenSorted(chain, msg.SRC)
		qPoly, _ := h.Len(chain, msg.POLY)
		fmt.Printf("  src tx queue size : %v\n", qSrc)
		fmt.Printf("  poly tx queue size: %v\n", qPoly)
	}
	qDelayed, _ := h.LenDelayed()
	fmt.Printf("Status shared:\n")
	fmt.Printf("  delayed tx queue size: %v\n", qDelayed)
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

func Skip(ctx *cli.Context) (err error) {
	hash := ctx.String("hash")
	return NewStatusHandler(config.CONFIG.Bus.Redis).Skip(hash)
}

func CheckSkip(ctx *cli.Context) (err error) {
	hash := ctx.String("hash")
	skip, err := NewStatusHandler(config.CONFIG.Bus.Redis).CheckSkip(hash)
	if skip {
		log.Info("Hash was marked to skip", "hash", hash)
	}
	return
}

func HandleCommand(method string, ctx *cli.Context) error {
	h, ok := _Handlers[method]
	if !ok {
		return fmt.Errorf("Unsupported subcommand %s", method)
	}
	return h(ctx)
}
