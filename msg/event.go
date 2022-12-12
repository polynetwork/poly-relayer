package msg

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

type InvalidPolyCommitEvent struct {
	*Tx
	Error error
}

func (o *InvalidPolyCommitEvent) Format() (title string, keys []string, values []interface{}, buttons []map[string]string) {
	keys = []string{"TxID", "DstProxy", "Method", "DstChain", "SrcChain", "PolyHash", "PolyKey", "Error"}
	var (
		method, dstProxy string
	)
	if o.MerkleValue != nil && o.MerkleValue.MakeTxParam != nil {
		method = o.MerkleValue.MakeTxParam.Method
		dstProxy = hex.EncodeToString(o.MerkleValue.MakeTxParam.ToContractAddress)
	}
	values = []interface{}{o.TxId, dstProxy, method, o.DstChainId, o.SrcChainId, o.PolyHash, o.PolyKey, o.Error}
	title = fmt.Sprintf("Suspicious poly commit from chain %d, CCMP for all chains will be paused, please check！", o.SrcChainId)
	return
}

type InvalidUnlockEvent struct {
	*Tx
	Error error
}

func (o *InvalidUnlockEvent) Format() (title string, keys []string, values []interface{}, buttons []map[string]string) {
	keys = []string{"DstProxy", "SrcChain", "DstChain", "PolyHash", "DstHash", "Error"}
	values = []interface{}{o.DstProxy, o.SrcChainId, o.DstAddress, o.DstChainId, o.PolyHash, o.DstHash, o.Error}
	title = fmt.Sprintf("Suspicious execute on chain %d, CCMP for all chains will be paused, please check！", o.DstChainId)
	return
}

type SetManagerProxyEvent struct {
	TxHash   string
	Contract string
	ChainId  uint64
	Manager  string
	Operator string
}

func (o *SetManagerProxyEvent) Format() (title string, keys []string, values []interface{}, buttons []map[string]string) {
	title = fmt.Sprintf("Suspicious set manager proxy event on chain %v", o.ChainId)
	keys = []string{"Hash", "Contract", "ChainId", "New Manager"}
	values = []interface{}{o.TxHash, o.Contract, o.ChainId, o.Manager}
	return
}

type BindProxyEvent struct {
	Contract  string
	TxHash    string
	ChainId   uint64
	ToChainId uint64
	ToProxy   string
	Operator  string
}

func (o *BindProxyEvent) Format() (title string, keys []string, values []interface{}, buttons []map[string]string) {
	title = fmt.Sprintf("Suspicious bind proxy event on chain %v", o.ChainId)
	keys = []string{"Hash", "Contract", "ChainId", "ToChainId", "ToProxy"}
	values = []interface{}{o.TxHash, o.Contract, o.ChainId, o.ToChainId, o.ToProxy}
	return
}

type TxEvent struct {
	TxHash  string
	ChainId string
	From    string
	To      string
	Path    string
	Value   string
	Message string
}

func (o *TxEvent) Format() (title string, keys []string, values []interface{}, buttons []map[string]string) {
	title = fmt.Sprintf("Tracking address event on chain %v", o.ChainId)
	keys = []string{"Hash", "From", "ChainId", "To", "Value", "Message"}
	values = []interface{}{o.TxHash, o.From, o.ChainId, o.To, o.Value, o.Message}
	return
}

type ChainHeightStuckEvent struct {
	Chain         string
	Duration      time.Duration
	CurrentHeight uint64
	Nodes         []string
}

func (o *ChainHeightStuckEvent) Format() (title string, keys []string, values []interface{}, buttons []map[string]string) {
	title = fmt.Sprintf("Chain node height stopped for %s", o.Chain)
	keys = []string{"CurrentHeight", "StuckFor", "Nodes"}
	values = []interface{}{o.CurrentHeight, o.Duration, o.Nodes}
	return
}

type BindAssetEvent struct {
	TxHash        string
	Contract      string
	ChainId       uint64
	FromAsset     string
	ToChainId     uint64
	Asset         string
	InitialAmount *big.Int
	Operator      string
}

func (o *BindAssetEvent) Format() (title string, keys []string, values []interface{}, buttons []map[string]string) {
	title = fmt.Sprintf("Suspicious bind asset event on chain %v", o.ChainId)
	keys = []string{"Hash", "Contract", "ChainId", "FromAsset", "ToChainId", "ToAsset", "InitialAmount"}
	values = []interface{}{o.TxHash, o.Contract, o.ChainId, o.FromAsset, o.ToChainId, o.Asset, o.InitialAmount}
	return
}

func ParseInt(value, ty string) (v *big.Int) {
	switch ty {
	case "Integer":
		v, _ = new(big.Int).SetString(value, 10)
	default:
		v, _ = new(big.Int).SetString(HexStringReverse(value), 16)
	}
	return
}

func HexReverse(arr []byte) []byte {
	l := len(arr)
	x := make([]byte, 0)
	for i := l - 1; i >= 0; i-- {
		x = append(x, arr[i])
	}
	return x
}

func HexStringReverse(value string) string {
	aa, _ := hex.DecodeString(value)
	bb := HexReverse(aa)
	return hex.EncodeToString(bb)
}
