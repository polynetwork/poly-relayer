package relayer

import (
	"fmt"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer/eth"
	"testing"
)

func TestValidate(t *testing.T) {
	conf, err := config.New("/Users/stefanliu/git/relayer/config.json")
	if err != nil { t.Fatal(err) }
	err = conf.Init()
	if err != nil { t.Fatal(err) }
	pl, err := PolyListener()
	if err != nil {
		t.Fatal(err)
	}
	lis, err := ChainListener(base.BSC, pl.SDK())
	if err != nil {
		t.Fatal(err)
	}
	txs, err := pl.ScanDst(20644363)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(len(txs))
	for _, tx := range txs {
		fmt.Println(tx.PolyHash)
		err = lis.(*eth.Listener).Validate(tx)
		if err != nil { t.Fatal(err) }
		fmt.Println("done")
	}
}
