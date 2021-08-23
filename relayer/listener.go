package relayer

import (
	"context"
	"sync"

	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
)

type Listener struct {
	handle ChainListener
	wg     *sync.WaitGroup
	ctx    context.Context
}

func (l *Listener) Init(config *config.ListenerConfig, ch chan msg.Message) error {
	return nil
}

func (l *Listener) Start(ctx context.Context, wg *sync.WaitGroup) error {
	l.wg = wg
	l.ctx = ctx
	l.wg.Add(1)
	return nil
}

func (l *Listener) start() error {
	return nil
}

func (l *Listener) Stop() error {
	l.wg.Wait()
	return nil
}
