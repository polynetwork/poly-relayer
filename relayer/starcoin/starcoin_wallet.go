package starcoin

import (
	"encoding/hex"
	"github.com/polynetwork/bridge-common/chains/starcoin"
	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/wallet"
	starcoin_types "github.com/starcoinorg/starcoin-go/types"
)

type StarcoinWallet struct {
	sdk        *starcoin.SDK
	Address    starcoin_types.AccountAddress
	PrivateKey string
	config     *wallet.Config
}

func NewStarcoinWallet(config *wallet.Config, sdk *starcoin.SDK) *StarcoinWallet {
	account, err := starcoin_types.ToAccountAddress(config.Address)
	if err != nil {
		log.Error("Parse account failed, {}", config.Address)
	}
	return &StarcoinWallet{sdk: sdk, Address: *account, PrivateKey: config.PrivateKey, config: config}
}

func (this *StarcoinWallet) asPrivateKey() starcoin_types.Ed25519PrivateKey {
	privateKeyBytes, _ := hex.DecodeString(this.PrivateKey)
	return privateKeyBytes
}

func (this *StarcoinWallet) address() string {
	return this.config.Address
}

func (w *StarcoinWallet) Init() (err error) {
	return
}
