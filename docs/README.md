## Poly Relayer Setup Guide


### Build and binaries

To build the binary, switch to the right branch [Branch Select](""), then run:


```

./build.sh testnet/mainnet

```


### Configuration

* Make sure necessory configuration is specifed in `config.json` [Sample]("../config.sample.json").

* Specify roles to enable in `roles.json` [Sample]("../roles.sample.json")


### Run


```
server --config ./config.json --roles ./roles.json

```


### About Roles 

* Header Sync

Some chains require `HeaderSync` process to run to submit chain headers to poly chain. 


* Source Chain -> Poly

`SyncTxSync` observes cross chain transactions from source chain, and push them to message queue.


`SrcTxCommit` consumes the message queue, and submit the cross chain transactions to poly.


* Poly -> Destination Chain

`PolyTxSync` observes cross chain transactions from poly chain and push them to message queue.

**ONLY ONE `PolyTxSync` PROCESS IS NEEDED FOR ALL CHAINS!**


`PolyTxCommit` consumes the message queue, and submit the cross chain transaction to the destination chain.






