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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/metrics"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

var (
	_PATCHER *bus.RedisTxBus
	_SKIP    *bus.RedisSkipCheck
)

func Http(ctx *cli.Context) (err error) {
	metrics.Init("relayer")
	// Insert web config
	port := ctx.Int("port")
	host := ctx.String("host")
	if port == 0 {
		port = config.CONFIG.Port
	}
	if host == "" {
		host = config.CONFIG.Host
	}

	// Init patcher
	_PATCHER = bus.NewRedisPatchTxBus(bus.New(config.CONFIG.Bus.Redis), 0)
	_SKIP = bus.NewRedisSkipCheck(bus.New(config.CONFIG.Bus.Redis))
	err = SetupController()
	if err != nil {
		return
	}

	go recordMetrics()
	http.HandleFunc("/api/v1/patch", PatchTx)
	http.HandleFunc("/api/v1/skip", SkipTx)
	http.HandleFunc("/api/v1/skipcheck", SkipCheckTx)
	http.HandleFunc("/api/v1/getManualData", controller.ComposeDstTx)
	http.ListenAndServe(fmt.Sprintf("%v:%v", host, port), nil)
	return
}

func recordMetrics() {
	h := NewStatusHandler(config.CONFIG.Bus.Redis)
	timer := time.NewTicker(2 * time.Second)
	for range timer.C {
		start := time.Now()
		for _, chain := range base.CHAINS {
			name := base.GetChainName(chain)
			name = strings.ReplaceAll(name, "(", "")
			name = strings.ReplaceAll(name, ")", "")
			latest, _ := h.Height(chain, bus.KEY_HEIGHT_CHAIN)
			header, _ := h.Height(chain, bus.KEY_HEIGHT_CHAIN_HEADER)
			mark, _ := h.Height(chain, bus.KEY_HEIGHT_HEADER)
			tx, _ := h.Height(chain, bus.KEY_HEIGHT_TX)
			metrics.Record(header, "height.header_sync.%s", name)
			metrics.Record(mark, "height.header_sync_mark.%s", name)
			metrics.Record(tx, "height.tx_sync.%s", name)
			metrics.Record(latest, "height.node.%s", name)
			if latest > 0 {
				headerDiff := int64(latest) - int64(header)
				txDiff := int64(latest) - int64(tx)
				if headerDiff < 0 {
					headerDiff = 0
				}
				if txDiff < 0 {
					txDiff = 0
				}
				metrics.Record(headerDiff, "height_diff.header_sync.%s", name)
				metrics.Record(txDiff, "height_diff.tx_sync.%s", name)
			}
			qSrc, _ := h.LenSorted(chain, msg.SRC)
			qPoly, _ := h.Len(chain, msg.POLY)
			metrics.Record(qSrc, "queue_size.src.%s", name)
			metrics.Record(qPoly, "queue_size.poly.%s", name)
		}
		qDelayed, _ := h.LenDelayed()
		metrics.Record(qDelayed, "queue_size.delayed")
		log.Info("metrics tick", "elapse", time.Since(start))
	}
}

func SkipTx(w http.ResponseWriter, r *http.Request) {
	hash := r.FormValue("hash")
	err := _SKIP.Skip(context.Background(), &msg.Tx{PolyHash: hash})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		Json(w, &msg.Tx{PolyHash: hash})
	}
}

func SkipCheckTx(w http.ResponseWriter, r *http.Request) {
	hash := r.FormValue("hash")
	tx := &msg.Tx{PolyHash: hash}
	skip, err := _SKIP.CheckSkip(context.Background(), tx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		tx.Skipped = skip
		Json(w, tx)
	}
}

func PatchTx(w http.ResponseWriter, r *http.Request) {
	height, _ := strconv.Atoi(r.FormValue("height"))
	chain, _ := strconv.Atoi(r.FormValue("chain"))
	limit, _ := strconv.Atoi(r.FormValue("limit"))
	hash := r.FormValue("hash")
	tx := &msg.Tx{
		SkipCheckFee: r.FormValue("free") == "true",
		DstGasPrice:  r.FormValue("price"),
		DstGasPriceX: r.FormValue("pricex"),
		DstGasLimit:  uint64(limit),
	}
	if chain == 0 {
		tx.PolyHeight = uint32(height)
		tx.PolyHash = hash
		tx.TxType = msg.POLY
	} else {
		tx.TxType = msg.SRC
		tx.SrcHash = hash
		tx.SrcHeight = uint64(height)
	}
	log.Info("Patching tx", "body", tx.Encode())
	err := _PATCHER.Patch(context.Background(), tx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		Json(w, tx)
	}
}

func Patch(ctx *cli.Context) (err error) {
	if ctx.Bool("auto") {
		return AutoPatch()
	}
	height := uint64(ctx.Int("height"))
	chain := uint64(ctx.Int("chain"))
	hash := ctx.String("hash")
	tx := &msg.Tx{
		SkipCheckFee: ctx.Bool("free"),
		DstGasPrice:  ctx.String("price"),
		DstGasPriceX: ctx.String("pricex"),
		DstGasLimit:  uint64(ctx.Int("limit")),
	}
	if chain == 0 {
		tx.PolyHeight = uint32(height)
		tx.PolyHash = hash
		tx.TxType = msg.POLY
	} else {
		tx.SrcHash = hash
		tx.TxType = msg.SRC
		tx.SrcHeight = height
		tx.SrcChainId = chain
	}
	err = bus.NewRedisPatchTxBus(bus.New(config.CONFIG.Bus.Redis), 0).Patch(context.Background(), tx)
	if err != nil {
		log.Error("Patch tx failed", "err", err)
		log.Json(log.ERROR, tx)
	}
	return
}

func Json(w http.ResponseWriter, data interface{}) {
	bytes, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}
