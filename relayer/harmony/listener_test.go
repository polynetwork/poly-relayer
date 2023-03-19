package harmony

import (
	"testing"

	"github.com/polynetwork/poly-relayer/config"
)

func TestGetLastEpochBlock(t *testing.T) {
	config.CONFIG.Env = "mainnet"
	prev, next := GetLastEpochBlock(23592960)
	if prev != 23592959 {
		t.Errorf("Prev for mainnet gives the wrong result")
	}
	if next != 23592959+EPOCH_BLOCKS_MAINNET {
		t.Errorf("Next for mainnet gives the wrong result")
	}
}
