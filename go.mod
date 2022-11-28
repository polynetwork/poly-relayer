module github.com/polynetwork/poly-relayer

go 1.15

require (
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/devfans/zion-sdk v0.0.24
	github.com/ethereum/go-ethereum v1.10.11
	github.com/go-redis/redis/v8 v8.11.3
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.2.1
	github.com/polynetwork/bridge-common v0.0.25-2
	github.com/urfave/cli/v2 v2.3.0
)

replace github.com/polynetwork/bridge-common => github.com/wuyachi/bridge-common v0.0.0-20221124093911-c47f24024f80
