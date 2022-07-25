module github.com/polynetwork/poly-relayer

go 1.15

require (
	github.com/KSlashh/poly-abi v0.0.0-20211223040949-f9bf1fe7c709
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/devfans/zion-sdk v0.0.11
	github.com/ethereum/go-ethereum v1.10.11
	github.com/go-redis/redis/v8 v8.11.3
	github.com/ontio/ontology-crypto v1.2.1
	github.com/polynetwork/bridge-common v0.0.14-2
	github.com/urfave/cli/v2 v2.3.0
)

replace (
	github.com/devfans/zion-sdk => github.com/wuyachi/zion-sdk v0.0.0-20220725105305-ff4e1c9a495d
	github.com/polynetwork/bridge-common => github.com/wuyachi/bridge-common v0.0.0-20220726031913-6929b4826ed5
)

//replace (
//	github.com/devfans/zion-sdk => ../zion-sdk
//	github.com/polynetwork/bridge-common => ../bridge-common-v2
//)
