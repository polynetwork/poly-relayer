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

package plt

import (
	"sort"

	"github.com/ethereum/go-ethereum/common"

	"github.com/polynetwork/poly-relayer/relayer/eth"
	pcom "github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/native/service/header_sync/quorum"
)

type Submitter = eth.Submitter

func isEpoch(cur, last []common.Address) bool {
	if len(cur) != len(last) {
		return true
	}
	sortAddrList(cur)
	sortAddrList(last)
	for i, v := range cur {
		if v != last[i] {
			return true
		}
	}
	return false
}

func sortAddrList(list []common.Address) {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Hex() < list[j].Hex()
	})
}

func valset2Bytes(vals []common.Address) []byte {
	vs := quorum.QuorumValSet(vals)
	sink := pcom.NewZeroCopySink(nil)
	vs.Serialize(sink)
	return sink.Bytes()
}

func bytes2Valset(raw []byte) ([]common.Address, error) {
	source := pcom.NewZeroCopySource(raw)
	vs := new(quorum.QuorumValSet)
	if err := vs.Deserialize(source); err != nil {
		return nil, err
	}
	return *vs, nil
}
