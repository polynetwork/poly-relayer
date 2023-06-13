module github.com/polynetwork/poly-relayer

go 1.15

require (
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/ethereum/go-ethereum v1.10.7
	github.com/go-redis/redis/v8 v8.11.3
	github.com/joeqian10/neo-gogogo v1.4.0
	github.com/onflow/cadence v0.23.3-patch.1
	github.com/onflow/flow-go v0.21.3
	github.com/onflow/flow-go-sdk v0.24.0
	github.com/onflow/flow-go/crypto v0.21.3
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.2.1
	github.com/ontio/ontology-go-sdk v1.11.4
	github.com/polynetwork/bridge-common v0.0.45-test.0.20230522083712-78bf294cba62
	github.com/polynetwork/poly v1.9.1-0.20220424092935-f54fa45801fe
	github.com/polynetwork/poly-go-sdk v0.0.0-20220425024155-af1927301211
	github.com/polynetwork/ripple-sdk v0.0.0-20220616022641-d64d4aa053fe
	github.com/portto/aptos-go-sdk v0.0.0-20221031095136-21bd4a704b90
	github.com/starcoinorg/starcoin-go v0.0.0-20220105024102-530daedc128b
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	google.golang.org/grpc v1.40.0

)

replace (
	github.com/rubblelabs/ripple v0.0.0-20220222071018-38c1a8b14c18 => github.com/siovanus/ripple v0.0.0-20220406100637-81f6afe283d9
	github.com/tendermint/tm-db/064 => github.com/tendermint/tm-db v0.6.4

)
