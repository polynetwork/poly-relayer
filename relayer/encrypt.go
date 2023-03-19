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
	"github.com/polynetwork/bridge-common/util"
	"github.com/urfave/cli/v2"
	"io/ioutil"
)

func EncryptFile(ctx *cli.Context) (err error) {
	file := ctx.String("file")
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	pass, err := util.ReadPassword("passphrase")
	if err != nil {
		return
	}
	cipherData := util.Encrypt(data, []byte(pass))
	err = ioutil.WriteFile(file+".encrypted", cipherData, 0644)
	return
}

func DecryptFile(ctx *cli.Context) (err error) {
	file := ctx.String("file")
	cipherData, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	pass, err := util.ReadPassword("passphrase")
	if err != nil {
		return
	}
	data := util.Decrypt(cipherData, []byte(pass))
	err = ioutil.WriteFile(file+".decrypted", data, 0644)
	return
}
