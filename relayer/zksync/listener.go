package zksync

import (
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/polynetwork/bridge-common/abi/zksync_l1_getter_abi"
	"github.com/polynetwork/bridge-common/base"
	ethcom "github.com/polynetwork/bridge-common/chains/eth"
	"github.com/polynetwork/bridge-common/chains/zion"
	"github.com/polynetwork/bridge-common/chains/zksync"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"math/big"
	"time"
)

type Listener struct {
	*eth.Listener
	sdk  *zksync.SDK
	name string
	ccm  common.Address
	ccd  common.Address
	l1   *zksync_l1_getter_abi.IGetters
}

func (l *Listener) Init(config *config.ListenerConfig, poly *zion.SDK) (err error) {
	if config.ChainId != base.ZKSYNC {
		return fmt.Errorf("zkSync chain id is incorrect in config %v", config.ChainId)
	}

	l.Listener = new(eth.Listener)
	err = l.Listener.Init(config, poly)
	if err != nil {
		return
	}

	l.name = base.GetChainName(config.ChainId)
	l.ccm = common.HexToAddress(config.CCMContract)
	l.ccd = common.HexToAddress(config.CCDContract)

	l.sdk, err = zksync.WithOptions(config.ChainId, config.Nodes, config.L1Node, time.Minute, 1)
	if err != nil {
		return fmt.Errorf("ontevm.WithOptions err:%v", err)
	}

	l.l1, err = zksync_l1_getter_abi.NewIGetters(common.HexToAddress(config.L1Contract), l.sdk.L1Node())
	if err != nil {
		return fmt.Errorf("zksync_l1_getter_abi.NewIGetters err:%v", err)
	}
	return
}

func (l *Listener) L1Node() *ethcom.Client {
	return l.sdk.L1Node()
}

func (l *Listener) GetEthL1BatchNumber(height int64) (uint64, error) {
	executed, err := l.l1.GetTotalBlocksExecuted(&bind.CallOpts{BlockNumber: big.NewInt(height)})
	if err != nil {
		return 0, err
	}
	return executed.Uint64(), nil
}

func (l *Listener) GetZkL1BatchNumber(height uint64) (uint64, error) {
	return l.sdk.Node().GetZkL1BatchNumber(height)
}

func (l *Listener) GetZkSyncConfirmedBlock(height uint64, limit uint64) (block uint64, wait bool, err error) {
	zkHeight, err := l.LatestHeight()
	if err != nil {
		err = fmt.Errorf("get latest height err:%s", err)
		return
	}
	log.Info("zk latest height", "height", zkHeight)

	ethHeight, err := l.L1Node().GetLatestFinalizedHeight()
	if err != nil {
		err = fmt.Errorf("get l1 latest height err:%s", err)
		return
	}

	ethL1BatchNumber, err := l.GetEthL1BatchNumber(int64(ethHeight))
	if err != nil {
		err = fmt.Errorf("get eth L1 batch number failed. height:%d, err:%s", ethHeight, err)
		return
	}
	log.Info("L1 latest confirmed batch", "ethL1BatchNumber", ethL1BatchNumber, "chain", l.name)

	left := height
	right := height + limit - 1
	if right > zkHeight {
		right = zkHeight
	}

	block, err = l.searchConfirmedBlock(ethL1BatchNumber, left, right)
	if err != nil {
		err = fmt.Errorf("zkSync searchConfirmedHeight failed. ethL1BatchNumber:%d, left:%d, right:%d err:%s", ethL1BatchNumber, left, right, err)
		return
	}
	if block == 0 {
		wait = true
	}
	log.Info("zk confirmed block", "block", block, "wait", wait)

	return
}

func (l *Listener) searchConfirmedBlock(ethL1BatchNumber uint64, left, right uint64) (uint64, error) {
	mid := right
	found := false
	for left <= right {
		zkL1BatchNumber, err := l.GetZkL1BatchNumber(mid)
		if err != nil {
			return 0, fmt.Errorf("get zk L1 batch number failed. height:%d, err:%s", mid, err)
		}

		if zkL1BatchNumber == 0 {
			right = mid - 1
			log.Info("zk block not submit to L1", "block", mid)
		} else if zkL1BatchNumber > ethL1BatchNumber {
			right = mid - 1
			log.Info("zk block not confirmed on L1", "block", mid, "zkL1Batch", zkL1BatchNumber)
		} else {
			found = true
			left = mid + 1
			log.Info("zk block confirmed on L1", "block", mid, "zkL1Batch", zkL1BatchNumber)
		}
		mid = (left + right) / 2
	}

	if found {
		return mid, nil
	} else {
		return 0, nil
	}

}
