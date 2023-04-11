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
	"encoding/binary"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/msg"

	"github.com/boltdb/bolt"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/poly-relayer/config"
)

const (
	BUCKET_TX     = "src_tx"
	BUCKET_META   = "src_meta"
	BUCKET_HEADER = "src_header"
	BUCKET_DATA   = "src_data"

	KEY_SRC_TX_HEIGHT     = "src_tx_height"
	KEY_SRC_HEADER_HEIGHT = "src_header_height"
)

type Store struct {
	chainID uint64
}

func NewStore(chainID uint64) (s *Store, err error) {
	s = &Store{
		chainID: chainID,
	}
	err = Init(config.CONFIG.BoltPath)
	if err != nil {
		return
	}

	for _, b := range [][]byte{s.BucketHeader(), s.BucketTx(), s.BucketMeta(), s.BucketData()} {
		err = InitBucket(b)
		if err != nil {
			return
		}
	}
	return
}

type Data struct {
	To   common.Address
	Data []byte
	Hash common.Hash
	Time uint64
}

type Tx struct {
	Hash    common.Hash
	Height  uint64
	ChainID uint64
	Value   []byte
	Key     []byte
	Delay   uint64
}

type Header struct {
	Hash   []byte
	Data   []byte
	Height uint64
}

func NewTx(tx *msg.Tx) *Tx {
	var key []byte
	if tx.TxType == msg.SRC {
		key = []byte(tx.SrcHash)
	} else if tx.TxType == msg.POLY {
		key = tx.PolyHash.Bytes()
	}

	return &Tx{Hash: msg.HexToHash(tx.SrcHash), Value: []byte(tx.Encode()), Height: tx.SrcHeight, ChainID: tx.SrcChainId, Key: key, Delay: tx.Delay}

}

func EncodeTx(tx *Tx) (key, value []byte) {
	value, err := rlp.EncodeToBytes(tx)
	if err != nil {
		log.Fatal("Unexpected rlp tx failure", "err", err)
	}
	return tx.Key, value
}

func DecodeTx(key, value []byte) (tx *Tx, err error) {
	tx = new(Tx)
	err = rlp.DecodeBytes(value, tx)
	return
}

func (s *Store) BucketTx() []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", base.ENV, BUCKET_TX, s.chainID))
}

func (s *Store) BucketMeta() []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", base.ENV, BUCKET_META, s.chainID))
}

func (s *Store) BucketHeader() []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", base.ENV, BUCKET_HEADER, s.chainID))
}

func (s *Store) BucketData() []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", base.ENV, BUCKET_DATA, s.chainID))
}

func (s *Store) GetTxHeight() (height uint64, err error) {
	h, err := Read(s.BucketMeta(), []byte(KEY_SRC_TX_HEIGHT))
	if err != nil {
		return
	}
	if len(h) < 8 {
		return 0, fmt.Errorf("chain %d, GetTxHeight from store failed, value invalid, value;%v", s.chainID, h)
	}
	height = binary.LittleEndian.Uint64(h)
	return
}

func (s *Store) SetTxHeight(height uint64) (err error) {
	value := make([]byte, 8)
	binary.LittleEndian.PutUint64(value, height)
	err = Write(s.BucketMeta(), []byte(KEY_SRC_TX_HEIGHT), value)
	return
}

func (s *Store) GetHeaderHeight() (height uint64, err error) {
	h, err := Read(s.BucketMeta(), []byte(KEY_SRC_HEADER_HEIGHT))
	if err != nil {
		return
	}
	height = binary.LittleEndian.Uint64(h)
	return
}

func (s *Store) SetHeaderHeight(height uint64) (err error) {
	value := make([]byte, 8)
	binary.LittleEndian.PutUint64(value, height)
	err = Write(s.BucketMeta(), []byte(KEY_SRC_HEADER_HEIGHT), value)
	return
}

func (s *Store) InsertTxs(txs []*Tx) (err error) {
	return Transact(s.BucketTx(), func(t *bolt.Bucket) error {
		for _, tx := range txs {
			k, v := EncodeTx(tx)
			e := t.Put(k, v)
			if e != nil {
				return e
			}
		}
		return nil
	})
}

func (s *Store) DeleteTxs(txs ...*Tx) (err error) {
	return Transact(s.BucketTx(), func(t *bolt.Bucket) error {
		for _, tx := range txs {
			k, _ := EncodeTx(tx)
			e := t.Delete(k)
			if e != nil {
				return e
			}
		}
		return nil
	})
}

func (s *Store) LoadTxs(max int) (txs []*Tx, err error) {
	f := func(k, v []byte) error {
		if len(txs) >= max {
			return nil
		}
		tx, err := DecodeTx(k, v)
		if err != nil {
			return err
		}
		txs = append(txs, tx)
		return nil
	}
	err = Scan(s.BucketTx(), func(t *bolt.Bucket) error {
		return t.ForEach(f)
	})
	return
}

func (s *Store) InsertData(hash common.Hash, data []byte, to common.Address) (err error) {
	return Transact(s.BucketData(), func(t *bolt.Bucket) error {
		tx := &Data{Hash: hash, Data: data, To: to, Time: uint64(time.Now().Unix())}
		v, err := rlp.EncodeToBytes(tx)
		if err != nil {
			return err
		}
		err = t.Put(tx.Hash.Bytes(), v)
		if err != nil {
			return err
		}
		return nil
	})
}

func (s *Store) DeleteData(list ...*Data) (err error) {
	return Transact(s.BucketData(), func(t *bolt.Bucket) error {
		for _, tx := range list {
			e := t.Delete(tx.Hash.Bytes())
			if e != nil {
				return e
			}
		}
		return nil
	})
}

func (s *Store) LoadData(max int) (list []*Data, err error) {
	f := func(k, v []byte) error {
		if len(list) >= max {
			return nil
		}
		tx := new(Data)
		err = rlp.DecodeBytes(v, tx)
		if err != nil {
			return err
		}
		list = append(list, tx)
		return nil
	}
	err = Scan(s.BucketData(), func(t *bolt.Bucket) error {
		return t.ForEach(f)
	})
	return
}

func (s *Store) InsertHeader(height uint64, hash, data []byte) (err error) {
	return Transact(s.BucketHeader(), func(t *bolt.Bucket) error {
		tx := &Header{Hash: hash, Data: data, Height: height}
		v, err := rlp.EncodeToBytes(tx)
		if err != nil {
			return err
		}
		key := make([]byte, 8)
		binary.LittleEndian.PutUint64(key, height)
		err = t.Put(key, v)
		if err != nil {
			return err
		}
		return nil
	})
}

func (s *Store) DeleteHeader(headers ...*Header) (err error) {
	return Transact(s.BucketHeader(), func(t *bolt.Bucket) error {
		for _, header := range headers {
			key := make([]byte, 8)
			binary.LittleEndian.PutUint64(key, header.Height)
			err = t.Delete(key)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) LoadHeaders(max int) (list []*Header, err error) {
	f := func(k, v []byte) error {
		if len(list) >= max {
			return nil
		}
		header := new(Header)
		err = rlp.DecodeBytes(v, header)
		if err != nil {
			return err
		}
		list = append(list, header)
		return nil
	}
	err = Scan(s.BucketHeader(), func(t *bolt.Bucket) error {
		return t.ForEach(f)
	})
	return
}
