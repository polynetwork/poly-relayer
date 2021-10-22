module github.com/polynetwork/poly-relayer

go 1.15

require (
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/devfans/zion v0.0.0-20211021022046-469977b05147
	github.com/devfans/zion-sdk v0.0.1
	github.com/ethereum/go-ethereum v1.10.11
	github.com/go-redis/redis/v8 v8.11.3
	github.com/joeqian10/neo-gogogo v1.4.0
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.0.9
	github.com/ontio/ontology-go-sdk v1.11.4
	github.com/polynetwork/bridge-common v0.0.19-beta
	github.com/polynetwork/poly v1.7.3-0.20210804073726-5d4f4d4a9371
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114035303-84e1615f4ad4
	github.com/urfave/cli/v2 v2.3.0
)

replace (
	github.com/devfans/zion-sdk => ../zion-sdk
	github.com/polynetwork/bridge-common => ../bridge-common
)
