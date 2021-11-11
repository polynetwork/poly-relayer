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

package poly

import (
	"context"
	"fmt"
	"math/big"

	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

func (s *Submitter) GetPolyParams(tx *msg.Tx) (err error) {
	if tx.PolyKey == "" {
		err = fmt.Errorf("Poly key not specified")
		return
	}

	tx.AnchorHeight = s.sdk.Height()
	tx.AnchorHeader, err = s.sdk.Node().HeaderByNumber(context.Background(), big.NewInt(int64(tx.AnchorHeight)))
	if err != nil {
		return err
	}
	proof, err := s.sdk.Node().GetProof(zion.CCM_ADDRESS.Hex(), tx.PolyKey, tx.AnchorHeight)
	if err != nil {
		return
	}
	tx.PolyAccountProof, err = msg.RlpEncodeStrings(proof.AccountProof)
	if err != nil {
		err = fmt.Errorf("rlp encode poly account proof failed", "poly_hash", tx.PolyHash, "err", err)
		return
	}
	if len(proof.StorageProofs) == 0 {
		err = fmt.Errorf("Failed to fetch poly storage proof, got empty", "poly_hash", tx.PolyHash)
		return
	}
	tx.PolyStorageProof, err = msg.RlpEncodeStrings(proof.StorageProofs[0].Proof)
	if err != nil {
		err = fmt.Errorf("rlp encode poly storage proof failed", "poly_hash", tx.PolyHash, "err", err)
	}
	return
}

func (s *Submitter) ComposeTx(tx *msg.Tx) (err error) {
	if msg.Empty(tx.PolyHash) {
		return fmt.Errorf("ComposeTx: Invalid poly hash")
	}
	/*
		if tx.DstPolyEpochStartHeight == 0 {
			return fmt.Errorf("ComposeTx: Dst chain poly height not specified")
		}
	*/

	if tx.PolyHeight == 0 {
		tx.PolyHeight, err = s.sdk.Node().GetBlockHeightByTxHash(tx.PolyHash)
		if err != nil {
			return
		}
	}
	if tx.MerkleValue.MakeTxParam == nil || !config.CONFIG.AllowMethod(tx.MerkleValue.MakeTxParam.Method) {
		method := "missing param"
		if tx.MerkleValue.MakeTxParam != nil {
			method = tx.MerkleValue.MakeTxParam.Method
		}
		return fmt.Errorf("%w Invalid poly tx, src chain(%v) tx(%s) method(%s)", msg.ERR_INVALID_TX, tx.SrcChainId, tx.PolyHash, method)
	}
	return s.GetPolyParams(tx)
}
