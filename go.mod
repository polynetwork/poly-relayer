module github.com/polynetwork/poly-relayer

go 1.15

require (
	github.com/astaxie/beego v1.12.3
	github.com/beego/beego/v2 v2.0.1
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/consensys/gurvy v0.3.8 // indirect
	github.com/ethereum/go-ethereum v1.10.7
	github.com/go-redis/redis v6.14.2+incompatible
	github.com/go-redis/redis/v8 v8.11.3
	github.com/joeqian10/neo-gogogo v0.0.0-20201214075916-44b70d175579
	github.com/joeqian10/neo3-gogogo v1.0.0
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/bridge-common v0.0.9
	github.com/polynetwork/poly v1.3.1
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114035303-84e1615f4ad4
	github.com/urfave/cli/v2 v2.3.0
)

// replace github.com/polynetwork/bridge-common v0.0.9 => github.com/devfans/bridge-common v0.0.9
replace github.com/polynetwork/bridge-common v0.0.9 => ../bridge-common
