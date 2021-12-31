# poly-relayer
Reimplement poly relayer

## Supported chains
| Chain   | Branch | HeaderSync | TxListen | TxCommit |
|--|--|-- |--|--|
|Ethereum |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Ontology |ont  |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Neo      |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|BSC      |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Heco     |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Okex     |ok   |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Polygon  |maitc|:white_check_mark:|:white_check_mark:|:white_check_mark:|
|O3       |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Palette  |plt  |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Arbitrum |main |:x:|:x:|:white_check_mark:|
|Xdai     |main |:x:|:x:|:white_check_mark:|
|Optimism |main |:x:|:x:|:white_check_mark:|
|Fantom   |main |:x:|:x:|:white_check_mark:|
|Avalanche|main |:x:|:x:|:white_check_mark:|
|Metis    |main |:x:|:x:|:white_check_mark:|

## TODOs
- [x] metrics, height, height_diff, queue length
- [x] graceful shutdown
- [x] state consistent across restart
- [x] configurable roles to run
- [x] Delayed retry queue for failed transactions
- [x] Transaction listen filters: methods, lockproxy contracts
- [x] Bridge check fee


## Docs

* [Setup](docs/README.md)

