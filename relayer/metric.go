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
	"strings"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/urfave/cli/v2"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/metrics"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

func Metric(ctx *cli.Context) (err error) {
	metrics.Init("relayer")
	// Insert web config
	port := ctx.Int("port")
	host := ctx.String("host")
	if port == 0 {
		port = config.CONFIG.MetricPort
	}
	if host == "" {
		host = config.CONFIG.MetricHost
	}

	go recordMetrics()
	web.BConfig.Listen.HTTPAddr = host
	web.BConfig.Listen.HTTPPort = port
	web.BConfig.RunMode = "prod"
	web.BConfig.AppName = "relayer"
	web.Run()
	return
}

func recordMetrics() {
	redis := bus.New(config.CONFIG.Bus.Redis)
	getHeight := func(id uint64, key bus.ChainHeightType) (uint64, error) {
		return bus.NewRedisChainStore(
			bus.ChainHeightKey{ChainId: id, Type: key}, redis, 0,
		).GetHeight(context.Background())
	}

	getLen := func(id uint64, ty msg.TxType) (uint64, error) {
		return bus.NewRedisTxBus(redis, id, ty).Len(context.Background())
	}

	timer := time.NewTicker(2 * time.Second)
	for range timer.C {
		for _, chain := range base.CHAINS {
			name := base.GetChainName(chain)
			name = strings.ReplaceAll(name, "(", "")
			name = strings.ReplaceAll(name, ")", "")
			latest, _ := getHeight(chain, bus.KEY_HEIGHT_CHAIN)
			header, _ := getHeight(chain, bus.KEY_HEIGHT_HEADER)
			tx, _ := getHeight(chain, bus.KEY_HEIGHT_TX)
			metrics.Record(header, "height.header_sync.%s", name)
			metrics.Record(tx, "height.tx_sync.%s", name)
			metrics.Record(latest, "height.node.%s", name)
			if latest > 0 {
				metrics.Record(latest-header, "height_diff.header_sync.%s", name)
				metrics.Record(latest-tx, "height_diff.tx_sync.%s", name)
			}
			qSrc, _ := getLen(chain, msg.SRC)
			qPoly, _ := getLen(chain, msg.POLY)
			metrics.Record(qSrc, "queue_size.src.%s", name)
			metrics.Record(qPoly, "queue_size.poly.%s", name)
		}
	}
}
