package relayer

import (
	"fmt"
	"testing"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/tools"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/polynetwork/poly-relayer/relayer/eth"
)

func TestValidate(t *testing.T) {
	conf, err := config.New("../config.json")
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

func TestValidateEvent(t *testing.T) {
	var ev tools.CardEvent
	ev = &msg.InvalidPolyCommitEvent{
		Error: fmt.Errorf("no"),
	}
	pause := ShouldPauseForEvent(ev)
	t.Logf("Pause %v %+v", pause, ev)
}
