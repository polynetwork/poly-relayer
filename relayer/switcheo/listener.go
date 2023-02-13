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

package switcheo

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"

	"github.com/polynetwork/poly-relayer/msg"
	tmtypes "github.com/tendermint/tendermint/abci/types"
	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
	"github.com/tendermint/tendermint/rpc/coretypes"
)

type Listener struct {
	rpcClient *rpchttp.HTTP
	poly      *zion.SDK
	config    *config.ListenerConfig
	name      string
	//state     bus.ChainStore // Header sync state
}

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	if config.ChainId != base.SWITCHEO {
		return fmt.Errorf("Switcheo chain id is incorrect in config %v", config.ChainId)
	}

	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.poly = poly

	//l.state = bus.NewRedisChainStore(
	//	bus.ChainHeightKey{ChainId: config.ChainId, Type: bus.KEY_HEIGHT_HEADER}, bus.New(config.Bus.Redis),
	//	config.Bus.HeightUpdateInterval,
	//)

	// TODO: make it able to take in multiple nodes
	l.rpcClient, err = rpchttp.New(config.Nodes[0])
	if err != nil {
		return fmt.Errorf("Switcheo rpcClient cannot be connected to rpcUrl %s", config.Nodes[0])
	}

	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	query := getTxQuery(height)
	page, perPage := 1, 100
	res, err := l.rpcClient.TxSearch(context.TODO(), query, true, &page, &perPage, "asc")
	if err != nil {
		return nil, err
	}

	for _, cosmosTx := range res.Txs {
		tx, err := l.createZionTx(cosmosTx)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

func (l *Listener) createZionTx(cosmosTx *coretypes.ResultTx) (*msg.Tx, error) {
	hashStr := hex.EncodeToString(cosmosTx.Hash)
	events := cosmosTx.TxResult.Events
	var makeProofEvent tmtypes.Event
	for _, event := range events {
		if event.Type == "zion_make_from_cosmos_proof" {
			makeProofEvent = event
		}
	}
	toChainIdStr, err := findEventAttributeValue(makeProofEvent, "to_chain_id")
	if err != nil {
		return nil, err
	}
	toChainId, err := strconv.ParseUint(toChainIdStr, 10, 64)
	if err != nil {
		return nil, err
	}
	rawData, err := findEventAttributeValue(makeProofEvent, "make_tx_param")
	if err != nil {
		return nil, err
	}
	log.Info("Found switcheo src cross chain tx", "hash", hashStr)
	tx := &msg.Tx{
		SrcHash:    hashStr,
		DstChainId: toChainId,
		SrcHeight:  uint64(cosmosTx.Height),
		SrcParam:   rawData,
		SrcChainId: l.config.ChainId,
	}
	l.Compose(tx)
	return tx, nil
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	hashBs, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	cosmosTx, err := l.rpcClient.Tx(context.Background(), hashBs, false)
	if err != nil {
		return nil, err
	}
	tx, err = l.createZionTx(cosmosTx)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	hashBs, err := hex.DecodeString(hash)
	if err != nil {
		return 0, err
	}
	tx, err := l.rpcClient.Tx(context.Background(), hashBs, false)
	if err != nil {
		return 0, err
	}
	return uint64(tx.Height), err
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	if tx.SrcHeight == 0 || len(tx.TxId) == 0 {
		return fmt.Errorf("tx missing attributes src height %v, txid %s", tx.SrcHeight, tx.TxId)
	}
	if len(tx.SrcParam) == 0 {
		return fmt.Errorf("src param is missing")
	}
	event, err := hex.DecodeString(tx.SrcParam)
	if err != nil {
		return fmt.Errorf("%s submitter decode src param error %v event %s", l.name, err, tx.SrcParam)
	}
	param, err := msg.DecodeTxParam(event)
	if err != nil {
		return
	}
	tx.Param = param
	tx.SrcEvent = event
	if err != nil {
		return
	}
	return
}

func (l *Listener) ListenCheck() time.Duration {
	duration := time.Second
	if l.config.ListenCheck > 0 {
		duration = time.Duration(l.config.ListenCheck) * time.Second
	}
	return duration
}

// not used
func (l *Listener) Nodes() chains.Nodes {
	return nil
}

func (l *Listener) ChainId() uint64 {
	return l.config.ChainId
}

func (l *Listener) Defer() int {
	return l.config.Defer
}

func (l *Listener) LatestHeight() (uint64, error) {
	status, err := l.rpcClient.Status(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to get status for chainId: %s and could be something wrong with RPC: %v", l.config.ChainId, err)
	}
	latestHeight := status.SyncInfo.LatestBlockHeight
	return uint64(latestHeight), nil
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	return
}

func (l *Listener) LastHeaderSync(force, last uint64) (height uint64, err error) {
	if l.poly == nil {
		err = fmt.Errorf("No poly sdk provided for listener chain %s", l.name)
		return
	}

	if force != 0 {
		return force, nil
	}
	h, err := l.poly.Node().GetInfoHeight(nil, l.config.ChainId)
	height = uint64(h)
	return
}

func (l *Listener) WaitTillHeight(ctx context.Context, height uint64, interval time.Duration) (uint64, bool) {
	if interval == 0 {
		return 0, false
	}
	for {
		h, err := l.LatestHeight()
		if err != nil {
			log.Error("Failed to get chain latest height err ", "chain", l.config.ChainId, "err", err)
		} else if h >= height {
			return h, true
		}
		select {
		case <-ctx.Done():
			return h, false
		case <-time.After(interval):
		}
	}
}

func findEventAttributeValue(event tmtypes.Event, key string) (string, error) {
	for _, attribute := range event.Attributes {
		attributeKey, err := base64.StdEncoding.DecodeString(attribute.Key)
		if err != nil {
			return "", err
		}
		if string(attributeKey) == key {
			attributeVal, err := base64.StdEncoding.DecodeString(attribute.Value)
			if err != nil {
				return "", err
			}
			return string(attributeVal), nil
		}
	}
	return "", fmt.Errorf("%s cannot be found in event %+v", key, event)
}

func getTxQuery(h uint64) string {
	return fmt.Sprintf("tx.height=%d AND zion_make_from_cosmos_proof.status='1'", h)
}
