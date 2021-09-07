package bus

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/go-redis/redis/v8"
	"github.com/polynetwork/bridge-common/base"
)

const (
	POLY_SYNC = String("poly_sync_running")

	KEY_HEIGHT_HEADER       ChainHeightType = "header_sync"
	KEY_HEIGHT_EXTRA_HEADER ChainHeightType = "header_extra_sync"
	KEY_HEIGHT_TX           ChainHeightType = "tx_sync"
)

type ChainHeightType string

type ChainStore interface {
	UpdateHeight(context.Context, uint64) error
	GetHeight(context.Context) (uint64, error)
	HeightMark(uint64) error
}

type ChainHeightKey struct {
	ChainId uint64
	Type    ChainHeightType
	Index   int
}

func (k ChainHeightKey) Key() string {
	return fmt.Sprintf("%s:relayer:%s:%v:%v", base.ENV, string(k.Type), k.ChainId, k.Index)
}

type RedisChainStore struct {
	height Key
	db     *redis.Client
	timer  *time.Ticker
}

func NewRedisChainStore(key Key, db *redis.Client, interval uint64) *RedisChainStore {
	return &RedisChainStore{
		height: key,
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

// A simple redis lock used to hint running status, avoid concurrencies
type Lock struct {
	key Key
	db  *redis.Client
	ctx context.Context
	wg  *sync.WaitGroup
}

func NewStatusLock(db *redis.Client, key Key) *Lock {
	return &Lock{key: key, db: db, ctx: context.Background()}
}

func (l *Lock) Start(ctx context.Context, wg *sync.WaitGroup) (ok bool, err error) {
	l.wg = wg
	l.ctx = ctx
	ok, err = l.db.SetNX(context.Background(), l.key.Key(), time.Now(), 60*time.Second).Result()
	if ok {
		go l.start()
	}
	return
}

func (l *Lock) start() {
	defer l.stop()
	l.wg.Add(1)
	timer := time.NewTicker(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-timer.C:
			_, err := l.db.Set(context.Background(), l.key.Key(), time.Now(), 60*time.Second).Result()
			if err != nil {
				logs.Error("Failed to update redis status lock for %s", l.key.Key())
			}
		}
	}
}

func (l *Lock) stop() {
	_, err := l.db.Del(context.Background(), l.key.Key()).Result()
	if err != nil {
		logs.Error("Failed to remove redis status lock for %s", l.key.Key())
	}
	l.wg.Done()
}
