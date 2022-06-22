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


package store

import (

	"github.com/boltdb/bolt"
)

var (
	db *bolt.DB
)

func Init(file string) (err error) {
	db, err = bolt.Open(file, 0600, nil)
	return
}

func InitBucket(bucket []byte) (err error) {
	err = db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucket)
		return e
	})
	return
}

func Close() (err error) {
	return db.Close()
}

func Read(bucket, key []byte) (value []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		value = tx.Bucket(bucket).Get(key)
		return nil
	})
	return
}

func Write(bucket, key, value []byte) (err error) {
	err = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put(key, value)
	})
	return
}

