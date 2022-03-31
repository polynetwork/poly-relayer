package msg

import (
	"fmt"
	"math/big"
	"time"
)

type InvalidPolyCommitEvent struct {
	*Tx
	Error error
}

func (o *InvalidPolyCommitEvent) Format() (title string, keys []string, values []interface{}, buttons []map[string]string) {
	keys = []string{"Amount", "Asset", "To", "SrcChain", "PolyHash", "SrcHash", "Error"}
	values = []interface{}{o.DstAmount.String(), o.DstAsset, o.DstAddress, o.SrcChainId, o.PolyHash, o.SrcHash, o.Error}
	title = fmt.Sprintf("Suspicious poly commit from chain %d", o.SrcChainId)
	return
}

type InvalidUnlockEvent struct {
	*Tx
	Error error
}

func (o *InvalidUnlockEvent) Format() (title string, keys []string, values []interface{}, buttons []map[string]string) {
	keys = []string{"Amount", "Asset", "To", "DstChain", "PolyHash", "DstHash", "Error"}
	values = []interface{}{o.DstAmount.String(), o.DstAsset, o.DstAddress, o.DstChainId, o.PolyHash, o.DstHash, o.Error}
	title = fmt.Sprintf("Suspicious unlock on chain %d", o.DstChainId)
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
