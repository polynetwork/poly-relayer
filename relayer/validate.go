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
	"github.com/polynetwork/bridge-common/tools"
	"github.com/polynetwork/poly-relayer/msg"
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
	return
}
