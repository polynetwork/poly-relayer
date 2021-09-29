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

import "github.com/polynetwork/bridge-common/util"

type FilterConfig struct {
	SrcProxyFilter bool
	DstProxyFilter bool
	SrcProxies     []string
	DstProxies     []string
}

func (c *FilterConfig) Init() {
	parse := func(addresses []string) []string {
		proxies := []string{}
		for _, p := range addresses {
			p = util.LowerHex(p)
			if len(p) > 0 {
				proxies = append(proxies, p)
			}
		}
		return proxies
	}
	c.SrcProxies = parse(c.SrcProxies)
	c.DstProxies = parse(c.DstProxies)
}

func filter(enabled bool, sets []string, value string) bool {
	if enabled {
		value = util.LowerHex(value)
		if len(value) == 0 {
			return false
		}

		for _, v := range sets {
			if v == value {
				return true
				break
			}
		}
		return false
	}
	return true
}

func (c *FilterConfig) Check(srcProxy, dstProxy string) bool {
	return c == nil || (filter(c.SrcProxyFilter, c.SrcProxies, srcProxy) &&
		filter(c.DstProxyFilter, c.DstProxies, dstProxy))
}
