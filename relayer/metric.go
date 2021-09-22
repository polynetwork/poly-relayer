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
	"github.com/beego/beego/v2/server/web"
	"github.com/urfave/cli/v2"

	"github.com/polynetwork/bridge-common/metrics"
	"github.com/polynetwork/poly-relayer/config"
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
	web.BConfig.Listen.HTTPAddr = host
	web.BConfig.Listen.HTTPPort = port
	web.BConfig.RunMode = "prod"
	web.BConfig.AppName = "relayer"
	web.Run()
	return
}
