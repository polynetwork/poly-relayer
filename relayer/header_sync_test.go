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
	"bytes"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/log"
)

func fatal(t *testing.T, err error) {
	if err != nil {
		t.Fatal(t)
	}
}

func TestHeaderSync(t *testing.T) {
	chain := base.BSC
	ps, err := PolySubmitter()
	fatal(t, err)
	l, err := ChainListener(chain, ps.Poly())
	fatal(t, err)
	height := uint64(13974592)
	b, err := ps.Poly().Node().GetSideChainHeader(chain, height)
	fatal(t, err)
	_, a, err := l.Header(height)
	fatal(t, err)
	if bytes.Equal(a, b) {
		log.Info("Found common ancestor", "chain", chain, "height", height)
	} else {
		fmt.Println(a)
		fmt.Println(b)
		log.Error("Hard forked block", "synced_hash", common.BytesToHash(a), "hash", common.BytesToHash(b), "a", a, "b", b, "height", height, "chain", chain)
		t.Fatalf("Header hash diff for chain %v", chain)
	}
}
