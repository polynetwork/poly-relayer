package relayer

import (
	"fmt"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/msg"
	"github.com/urfave/cli/v2"
	"net/http"
	"strconv"
)

func HttpSubmit(c *cli.Context) (err error) {
	// Insert HttpSubmit web config
	port := c.Int("port")
	host := c.String("host")
	if port == 0 {
		port = config.CONFIG.SubmitPort
	}
	if host == "" {
		host = config.CONFIG.SubmitHost
	}
	http.HandleFunc("/api/v1/httpsubmit", SubmitTx)
	http.ListenAndServe(fmt.Sprintf("%v:%v", host, port), nil)
	return
}

func SubmitTx(w http.ResponseWriter, r *http.Request) {
	height, _ := strconv.Atoi(r.FormValue("height"))
	chain, _ := strconv.Atoi(r.FormValue("chain"))
	hash := r.FormValue("hash")
	limit, _ := strconv.Atoi(r.FormValue("limit"))
	sender := r.FormValue("sender")
	free := r.FormValue("free") == "true"
	tx := &msg.Tx{
		SkipCheckFee: free,
		DstGasPrice:  r.FormValue("price"),
		DstGasPriceX: r.FormValue("pricex"),
		DstGasLimit:  uint64(limit),
	}
	if len(sender) > 0 {
		tx.DstSender = sender
	}
	txlog, err := relayTx(uint64(height), uint64(chain), hash, free, tx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		Json(w, txlog)
	}
}
