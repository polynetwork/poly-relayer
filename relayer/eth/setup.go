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

package eth

import (
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"
	"math/big"
)

func init() {
	wallet.SetGasLimit(base.ARBITRUM, 4000000)
	wallet.SetGasLimit(base.OPTIMISM, 4000000)
	wallet.SetGasLimit(base.ZKSYNC, 1300000)

	//balanceLimit
	wallet.SetBalanceLimit(base.BSC, util.SetDecimals(big.NewInt(1), 16))
	wallet.SetBalanceLimit(base.OPTIMISM, util.SetDecimals(big.NewInt(1), 15))
	wallet.SetBalanceLimit(base.ETH, util.SetDecimals(big.NewInt(1), 16))
	wallet.SetBalanceLimit(base.ARBITRUM, util.SetDecimals(big.NewInt(1), 15))
	wallet.SetBalanceLimit(base.METIS, util.SetDecimals(big.NewInt(1), 16))
}
