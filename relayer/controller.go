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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/polynetwork/poly-relayer/msg"
	"net/http"
	"strconv"
	"strings"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/poly-relayer/config"
	po "github.com/polynetwork/poly-relayer/relayer/poly"
)

var controller *Controller

func SetupController() (err error) {
	submitter, err := PolySubmitter()
	if err != nil {
		return
	}
	listener, err := PolyListener()
	if err != nil {
		return
	}

	controller = &Controller{
		listener, submitter,
	}
	return
}

type Controller struct {
	listener  *po.Listener
	submitter *po.Submitter
}

type AptosUnlockPayload struct {
	TypeArgument string
	Proof        []byte
	RawHeader    []byte
	HeaderProof  []byte
	Anchor       []byte
	HeaderSig    []byte
}

func (c *Controller) SubmitTx(w http.ResponseWriter, r *http.Request) {
	height, _ := strconv.Atoi(r.FormValue("height"))
	chain, _ := strconv.Atoi(r.FormValue("chain"))
	limit, _ := strconv.Atoi(r.FormValue("limit"))
	hash := r.FormValue("hash")
	sender := r.FormValue("sender")
	price := r.FormValue("price")
	pricex := r.FormValue("pricex")
	free := r.FormValue("free") == "true"
	txs, err := relayTx(uint64(chain), uint64(height), hash, sender, free, price, pricex, uint64(limit), false)
	log.Info("Submit executed", "err", err)
	resp := map[string]interface{}{}
	resp["err"] = err
	resp["txs"] = txs
	resp["size"] = len(txs)
	Json(w, resp)
}

func (c *Controller) ComposeDstTx(w http.ResponseWriter, r *http.Request) {
	hash := r.FormValue("hash")
	if hash == "" {
		http.Error(w, "request not invalid", http.StatusBadRequest)
		return
	}
	log.Info("Composing dst tx", "poly_hash", hash)
	data, err := c.composeDstTx(hash)
	if err != nil {
		log.Error("Failed to compose dst tx", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		Json(w, data)
	}
}

func (c *Controller) composeDstTx(hash string) (data interface{}, err error) {
	tx, err := c.listener.ScanTx(hash)
	if err != nil || tx == nil || util.LowerHex(tx.PolyHash) != util.LowerHex(hash) {
		err = fmt.Errorf("Failed to find poly tx %s, err %v", hash, err)
		return
	}
	sub, err := DstSubmitter(tx.DstChainId)
	if err != nil {
		return
	}
	err = sub.ProcessTx(tx, c.submitter.ComposeTx)
	if err != nil {
		return
	}
	payload := map[string]interface{}{}
	conf := config.CONFIG.Chains[tx.DstChainId]
	if conf != nil {
		payload["dst_ccm"] = conf.CCMContract
	}
	switch tx.DstChainId {
	case base.ONT:
		payload["data"] = tx.Extra
	case base.APTOS:
		aptosPayload, err := getAptosUnlockPayload(tx)
		if err != nil {
			err = fmt.Errorf("get aptos paylod err %v", err)
			return
		}
		marshal, err := json.Marshal(aptosPayload)
		if err != nil {
			err = fmt.Errorf("marshal aptos paylod err %v", err)
			return
		}
		payload["data"] = string(marshal)
	default:
		payload["data"] = hex.EncodeToString(tx.DstData)
	}
	data = payload
	return
}

func getAptosUnlockPayload(tx *msg.Tx) (*AptosUnlockPayload, error) {
	// tx.ToAssetAddress: 0x1::coin::Coin<0xf12a4ff673797d20307f081103186c6a725a6c8609a551bdc13ee30862f2ce15::nb::NBCoin>
	paylod := new(AptosUnlockPayload)
	parts := strings.Split(tx.ToAssetAddress, "<")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid toAssetAddress: %s", tx.ToAssetAddress)
	}

	paylod.TypeArgument = strings.TrimSuffix(parts[1], ">")

	proof, err := hex.DecodeString(tx.AuditPath)
	if err != nil {
		return nil, fmt.Errorf("%s failed to decode audit path %v", err)
	}
	paylod.Proof = proof

	paylod.RawHeader = tx.PolyHeader.GetMessage()

	headerProof, err := hex.DecodeString(tx.AnchorProof)
	if err != nil {
		return nil, fmt.Errorf("%s processPolyTx decode anchor proof hex error %v", err)
	}
	paylod.HeaderProof = headerProof

	var anchor []byte
	if tx.AnchorHeader != nil {
		anchor = tx.AnchorHeader.GetMessage()
	}
	paylod.Anchor = anchor

	paylod.HeaderSig = tx.PolySigs

	return paylod, nil
}
