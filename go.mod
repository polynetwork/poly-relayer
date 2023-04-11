module github.com/polynetwork/poly-relayer

go 1.15

require (
	github.com/Zilliqa/gozilliqa-sdk v1.2.1-0.20210927032600-4c733f2cb879
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.22.1
	github.com/devfans/zion-sdk v0.0.27
	github.com/ethereum/go-ethereum v1.10.11
	github.com/go-redis/redis/v8 v8.11.3
	github.com/joeqian10/neo3-gogogo v1.2.1
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.2.1
	github.com/ontio/ontology-go-sdk v1.11.4
	github.com/polynetwork/bridge-common v0.0.41-2
	github.com/polynetwork/ripple-sdk v0.0.0-20220616022641-d64d4aa053fe
	github.com/portto/aptos-go-sdk v0.0.0-20230118094238-99813673238c
	github.com/rubblelabs/ripple v0.0.0-20220222071018-38c1a8b14c18
	github.com/tendermint/tendermint v0.35.9
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
)

replace github.com/rubblelabs/ripple => github.com/siovanus/ripple v0.0.0-20230113075118-4a31480c1af2
