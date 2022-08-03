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

package msg

import "errors"

var (
	ERR_INVALID_TX            = errors.New("Invalid TX")
	ERR_TX_BYPASS             = errors.New("Tx bypass")
	ERR_PROOF_UNAVAILABLE     = errors.New("Tx proof unavailable")
	ERR_HEADER_INCONSISTENT   = errors.New("Header inconsistent")
	ERR_HEADER_MISSING        = errors.New("Header missing")
	ERR_TX_EXEC_FAILURE       = errors.New("Tx exec failure")
	ERR_FEE_CHECK_FAILURE     = errors.New("Tx fee check failure")
	ERR_HEADER_SUBMIT_FAILURE = errors.New("Header submit failure")
	ERR_TX_EXEC_ALWAYS_FAIL   = errors.New("Tx exec always fail")
	ERR_EPOCH_MISS            = errors.New("Poly epoch miss")
	ERR_TX_PENDING            = errors.New("Tx pending")
	ERR_LOW_BALANCE           = errors.New("Insufficient balance")
	ERR_PAID_FEE_TOO_LOW      = errors.New("Paid fee too low")

	ERR_TX_VOILATION     = errors.New("Possible cross chain voilation")
	ERR_TX_PROOF_MISSING = errors.New("Possible cross chain proof missing")

	ERR_SIGNER_ALREADY_EXIST = errors.New("signer already exist")
)
