# poly-relayer
Reimplement poly relayer

## Supported chains
| Chain | Branch | HeaderSync | TxListen | TxCommit |
|--|--|--|--|--|
|Ethereum|main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Ontology|ont  |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Neo     |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Neo3    |main |:x:|:x:|:x:|
|BSC     |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Heco    |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Okex    |ok   |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Polygon |maitc|:white_check_mark:|:white_check_mark:|:white_check_mark:|
|O3      |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Palette |main |:white_check_mark:|:white_check_mark:|:white_check_mark:|
|Switcheo|main |:x:|:x:|:x:|
|Arbitrum|main |:x:|:x:|:x:|

## TODOs
- [x] metrics, height, height_diff, queue length
- [x] graceful shutdown
- [x] state consistent across restart
- [x] configurable roles to run
- [x] Delayed retry queue for failed transactions
- [x] Transaction listen filters: methods, lockproxy contracts
- [x] Bridge check fee
