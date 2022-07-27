module github.com/polynetwork/poly-relayer

go 1.15

require (
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
	github.com/devfans/zion-sdk => github.com/wuyachi/zion-sdk v0.0.0-20220727024926-4a47382fc8e7
	github.com/polynetwork/bridge-common => github.com/wuyachi/bridge-common v0.0.0-20220727081618-be166a2d1bfc
)

//replace (
//	github.com/devfans/zion-sdk => ../zion-sdk
//	github.com/polynetwork/bridge-common => ../bridge-common-v2
//)
