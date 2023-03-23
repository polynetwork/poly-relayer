package starcoin

import (
	"github.com/ontio/ontology/common/log"
	"github.com/starcoinorg/starcoin-go/client"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCrossChainData(t *testing.T) {
	data := "0x1048b75ec5bb72e54bca2633c36ca3eb0410000000000000000000000000000000004140000000000000005800000000000000100000000000000048b75ec5bb72e54bca2633c36ca3eb040f000000000000007a696f6e5f6c6f636b5f70726f787900003e010000000000001048b75ec5bb72e54bca2633c36ca3eb04c102e000000000000000f80000000000000020010000000000003e0100000000000069010000000000008101000000000000a3010000000000001000000000000000000000000000000000000000000000002000000000000000f5220b972969f97023a9669e68c65cf6e87d9a1ad635e1ef5e6208c232b63c16410000000000000040000000000000005800000000000000100000000000000048b75ec5bb72e54bca2633c36ca3eb040f000000000000007a696f6e5f6c6f636b5f70726f78790000100000000000000048b75ec5bb72e54bca2633c36ca3eb040600000000000000756e6c6f636b00000000000000000000000000000000000000003e000000000000000c3078313a3a5354433a3a53541048b75ec5bb72e54bca2633c36ca3eb041027000000000000000000000000000000000000000000000000000000000000"
	eventData, err := HexToBytes(data)
	if err != nil {
		log.Errorf("Scan |  hex.DecodeString error :%s", err.Error())
	}
	crossChainEventData, err := BcsDeserializeCrossChainEvent(eventData)
	if err != nil {
		log.Errorf("fetchLockDepositEvents - BcsDeserializeCrossChainDepositEvent error :%s", err.Error())
	}
	assert.Equal(t, crossChainEventData.ToChainId, uint64(318), "Not equal")
	log.Info(client.BytesToHexString(crossChainEventData.ToContract))
	log.Info(client.BytesToHexString(crossChainEventData.ProxyOrAssetContract))
	log.Info(client.BytesToHexString(crossChainEventData.Sender))
	log.Info(client.BytesToHexString(crossChainEventData.TxId))
}
