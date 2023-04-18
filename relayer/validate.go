/*
 * Copyright (C) 2022 The poly network Authors
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
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/tools"
	"github.com/polynetwork/poly-relayer/bus"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"github.com/polynetwork/poly-relayer/relayer/zion"
)

type IValidator interface {
	Validate(*msg.Tx) error
}

type Validator struct {
	vs       func(uint64) IValidator
	listener IChainListener
	outputs  chan tools.CardEvent
}

func StartValidator(vs func(uint64) IValidator, listener IChainListener, outputs chan tools.CardEvent) (err error) {
	v := &Validator{vs, listener, outputs}
	go v.start()
	return
}

func (v *Validator) start() (err error) {
	chainID := v.listener.ChainId()
	log.Info("Starting validator for events", "chain", chainID)
	status := NewStatusHandler(config.CONFIG.Bus.Redis)
	height, _ := status.Height(chainID, bus.KEY_HEIGHT_VALIDATOR)
	if height == 0 {
		height, err = v.listener.LatestHeight()
		if err != nil {
			log.Fatal("Failed to get latest height", "chain", chainID, "err", err)
		}
	}

	var (
		latest   uint64
		listener *eth.Listener
		scan     func(uint64) ([]*msg.Tx, error)
	)

	if chainID > 0 {
		listener = v.listener.(*eth.Listener)
		scan = listener.ScanDst
	} else {
		scan = v.listener.(*zion.Listener).ScanDst
	}

	for {
		height++
		if latest < height {
			latest, _ = v.listener.Nodes().WaitTillHeight(context.Background(), height, v.listener.ListenCheck())
		}
		log.Info("Validating txs in block", "height", height, "chain", chainID)
		txs, err := scan(height)
		if err == nil {
			for _, tx := range txs {
				hash := tx.PolyHash
				if chainID > 0 {
					hash = common.HexToHash(tx.DstHash)
				}
				validator := v.vs(tx.SrcChainId)
				if validator == nil {
					log.Info("Skipping validating tx", "chain", chainID, "origin", tx.SrcChainId, "hash", hash)
					continue
				}
				for i := 0; i < 100; i++ {
					err = validator.Validate(tx)
					print := log.Info
					if err != nil {
						print = log.Error
					}
					print("Validating tx", "chain", chainID, "origin", tx.SrcChainId, "hash", hash, "err", err)
					if err == nil || errors.Is(err, msg.ERR_TX_VOILATION) {
						break
					}
					time.Sleep(time.Second)
				}
				if err != nil {
					if chainID > 0 {
						v.outputs <- &msg.InvalidUnlockEvent{Tx: tx, Error: fmt.Errorf("invalid VerifyHeaderAndExecuteTxEvent event on chain %d, %v", tx.DstChainId, err)}
					} else {
						v.outputs <- &msg.InvalidPolyCommitEvent{Tx: tx, Error: fmt.Errorf("invalid poly commit tx from chain %d, %v", tx.SrcChainId, err)}
					}
				}
			}
			if height%100 == 0 {
				status.SetHeight(chainID, bus.KEY_HEIGHT_VALIDATOR, height)
			}
			if listener != nil {
				// Scan proxy events
				listener.ScanEvents(height, v.outputs)
			}
		} else {
			log.Error("Failed to scan txs in block", "chain", chainID, "err", err)
			time.Sleep(time.Second)
			height--
		}
	}

}
