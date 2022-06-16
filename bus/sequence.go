package bus

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/poly-relayer/msg"
	"time"
)

const (
	sequenceExpiration = time.Minute * 10
	txExpiration       = time.Hour * 24 * 30
)

type Sequence interface {
	NowSequence(ctx context.Context, chain uint64) (string, error)
	SetSequence(ctx context.Context, chain uint64, sequence string) error
	GetTx(ctx context.Context, chain uint64, sequence string) (*msg.Tx, error)
	AddTx(ctx context.Context, chain uint64, sequence string, tx *msg.Tx) error
	DelTx(ctx context.Context, chain uint64, sequence string) error
}

type RedisChainSequence struct {
	Key
	db *redis.Client
}

func NewRedisChainSequence(db *redis.Client) *RedisChainSequence {
	return &RedisChainSequence{String("sequence"), db}
}

func (b *RedisChainSequence) NowSequence(ctx context.Context, chain uint64) (sequence string, err error) {
	k := fmt.Sprintf("%v_%v", b.Key.Key(), chain)
	sequence, err = b.db.Get(ctx, k).Result()
	if err != nil {
		err = errors.New("NowSequence err:" + "key:" + k + err.Error())
		return
	}
	return
}

func (b *RedisChainSequence) SetSequence(ctx context.Context, chain uint64, sequence string) (err error) {
	k := fmt.Sprintf("%v_%v", b.Key.Key(), chain)
	_, err = b.db.Set(ctx, k, sequence, sequenceExpiration).Result()
	if err != nil {
		err = errors.New("SetSequence err:" + "key:" + k + "value:" + sequence + err.Error())
	}
	return
}

func (b *RedisChainSequence) GetTx(ctx context.Context, chain uint64, sequence string) (tx *msg.Tx, err error) {
	k := fmt.Sprintf("%v_%v_%v", b.Key.Key(), chain, sequence)
	resp, err := b.db.Get(ctx, k).Result()
	if err != nil {
		err = errors.New("GetTx err:" + "key:" + k + err.Error())
		return
	}
	tx = new(msg.Tx)
	err = tx.Decode(resp)
	return
}

func (b *RedisChainSequence) AddTx(ctx context.Context, chain uint64, sequence string, tx *msg.Tx) (err error) {
	k := fmt.Sprintf("%v_%v_%v", b.Key.Key(), chain, sequence)
	_, err = b.db.Set(ctx, k, tx.Encode(), txExpiration).Result()
	if err != nil {
		err = errors.New("AddTx err:" + "key:" + k + err.Error())
		return
	}
	return
}

func (b *RedisChainSequence) DelTx(ctx context.Context, chain uint64, sequence string) (err error) {
	k := fmt.Sprintf("%v_%v_%v", b.Key.Key(), chain, sequence)
	_, err = b.db.Del(ctx, k).Result()
	if err != nil {
		err = errors.New("DelTx err:" + "key:" + k + err.Error())
		return
	}
	return
}
