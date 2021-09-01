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
	"sync"

	"github.com/beego/beego/v2/core/logs"
	"github.com/polynetwork/poly-relayer/config"
)

type Server struct {
	ctx    context.Context
	wg     *sync.WaitGroup
	config *config.Config
}

func Start(ctx context.Context, wg *sync.WaitGroup, config *config.Config) error {
	server := &Server{ctx, wg, config}
	return server.Start()
}

func (s *Server) Start() (err error) {
	if s.config.Poly != nil {
		err = s.StartPolyTxSync(s.config.Poly.PolyTxSync)
		if err != nil {
			return
		}
	}
	for _, chain := range s.config.Chains {
		err = s.StartHeaderSync(chain.HeaderSync)
		if err != nil {
			return
		}
		err = s.StartSrcTxSync(chain.SrcTxSync)
		if err != nil {
			return
		}
		err = s.StartSrcTxCommit(chain.SrcTxCommit)
		if err != nil {
			return
		}
		err = s.StartPolyTxCommit(chain.PolyTxCommit)
		if err != nil {
			return
		}
	}
	return
}

func (s *Server) StartHeaderSync(config *config.HeaderSyncConfig) (err error) {
	if config == nil || !config.Enabled {
		return
	}
	logs.Info("Starting header sync role... with config:\n%+v\n", *config)
	h := NewHeaderSyncHandler(config, nil, nil)
	err = h.Init(s.ctx, s.wg)
	if err != nil {
		return fmt.Errorf("Failed to init header sync handler for chain %d error %v", config.ChainId, err)
	}
	err = h.Start()
	if err != nil {
		return fmt.Errorf("Failed to start header sync handler for chain %d error %v", config.ChainId, err)
	}
	return
}

func (s *Server) StartPolyTxSync(config *config.PolyTxSyncConfig) (err error) {
	if config == nil || !config.Enabled {
		return
	}
	logs.Info("Starting poly tx sync role...with config:\n%+v\n", *config)
	return
}

func (s *Server) StartSrcTxSync(config *config.SrcTxSyncConfig) (err error) {
	if config == nil || !config.Enabled {
		return
	}
	logs.Info("Starting src tx sync role... with config:\n%+v\n", *config)
	return
}

func (s *Server) StartSrcTxCommit(config *config.SrcTxCommitConfig) (err error) {
	if config == nil || !config.Enabled {
		return
	}
	logs.Info("Starting src tx commit role... with config:\n%+v\n", *config)
	return
}

func (s *Server) StartPolyTxCommit(config *config.PolyTxCommitConfig) (err error) {
	if config == nil || !config.Enabled {
		return
	}
	logs.Info("Starting poly tx commit role... with config:\n%+v\n", *config)
	return
}
