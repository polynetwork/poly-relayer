package bus

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/bridge-common/base"
)

type ChainStore interface {
	UpdateHeight(context.Context, uint64) error
	GetHeight(context.Context) (uint64, error)
	HeightMark(uint64)
}

type ChainHeightKey uint64

func (k ChainHeightKey) Key() string {
	return fmt.Sprintf("%s_RELAYER_CHAIN_%v", base.ENV, k)
}

type RedisChainStore struct {
	height Key
	db     *redis.Client
	timer  *time.Ticker
}

func NewRedisChainStore(chainId uint64, db *redis.Client, interval uint64) *RedisChainStore {
	return &RedisChainStore{
		height: ChainHeightKey(chainId),
		db:     db,
		timer:  time.NewTicker(time.Duration(interval) * time.Second),
	}
}

func (s *RedisChainStore) UpdateHeight(ctx context.Context, height uint64) error {
	_, err := s.db.Set(ctx, s.height.Key(), height, 0).Result()
	if err != nil {
		return fmt.Errorf("Failed to update height %v", err)
	}
	return nil
}

func (s *RedisChainStore) HeightMark(height uint64) error {
	select {
	case <-s.timer.C:
	default:
		return nil
	}
	return s.UpdateHeight(context.Background(), height)
}

func (s *RedisChainStore) GetHeight(ctx context.Context) (height uint64, err error) {
	v, err := s.db.Get(ctx, s.height.Key()).Result()
	if err != nil {
		return 0, fmt.Errorf("Get chain height error %v", err)
	}
	h, _ := strconv.Atoi(v)
	height = uint64(h)
	return
}
