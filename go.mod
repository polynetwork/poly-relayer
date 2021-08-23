module github.com/polynetwork/poly-relayer

go 1.15

require (
	github.com/astaxie/beego v1.12.3
	github.com/beego/beego/v2 v2.0.1
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/ethereum/go-ethereum v1.9.15
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/bridge-common v0.0.9
	github.com/polynetwork/poly v1.3.1
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114035303-84e1615f4ad4
)

replace github.com/polynetwork/bridge-common v0.0.9 => github.com/devfans/bridge-common v0.0.9
