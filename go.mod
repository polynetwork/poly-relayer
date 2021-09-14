module github.com/polynetwork/poly-relayer

go 1.15

require (
	github.com/beego/beego/v2 v2.0.1
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/cosmos/cosmos-sdk v0.39.2
	github.com/ethereum/go-ethereum v1.10.7
	github.com/go-redis/redis/v8 v8.11.3
	github.com/joeqian10/neo-gogogo v0.0.0-20201214075916-44b70d175579
	github.com/joeqian10/neo3-gogogo v1.0.0
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.0.9
	github.com/ontio/ontology-go-sdk v1.11.4
	github.com/polynetwork/bridge-common v0.0.9
	github.com/polynetwork/poly v1.3.1
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114035303-84e1615f4ad4
	github.com/urfave/cli/v2 v2.3.0
)

// replace github.com/polynetwork/bridge-common v0.0.9 => github.com/devfans/bridge-common v0.0.9
replace github.com/polynetwork/bridge-common v0.0.9 => ../bridge-common

replace (
	github.com/cosmos/cosmos-sdk => github.com/okex/cosmos-sdk v0.39.2-exchain9
	github.com/ethereum/go-ethereum => github.com/ethereum/go-ethereum v1.9.25
	github.com/okex/exchain => github.com/okex/exchain v0.18.4
	github.com/tendermint/iavl => github.com/okex/iavl v0.14.3-exchain
	github.com/tendermint/tendermint => github.com/okex/tendermint v0.33.9-exchain6
)
