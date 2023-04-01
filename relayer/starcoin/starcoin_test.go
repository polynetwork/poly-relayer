package starcoin

import (
	"github.com/polynetwork/bridge-common/log"
	"testing"
)

func TestGetAssetCoinTypeTag(t *testing.T) {
	coinTypeTag, _ := getAssetCoinTypeTag("0x00000000000000000000000000000001::STC::STC")
	log.Info("Coin type tag: ", coinTypeTag)
}

//func TestG(t *testing.T) {
//	txJson := "{\"TxType\":2,\"Attempts\":1,\"TxId\":\"2c38e0fd45b4eb4a73f7fe12749bd1229dde283399bffabd4e90589c1e561f57\",\"SrcChainId\":318,\"SrcProxy\":\"000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000010f08ac0c1c6c8f2be528b35824755054000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f7a696f6e5f6c6f636b5f70726f78790000000000000000000000000000000000\",\"PolyHash\":\"0x983561882d758959e2022006b4d0848dfd6a677fd2c06e5ab80466e992fa9565\",\"PolyHeight\":178220,\"PolyKey\":\"0x3b7cfcc4efb9d360c5c96cfdfe2c4b3d8feeaa303a14cea1bd2e1e0d76e39362\",\"AnchorHeight\":179948,\"PolyParam\":\"f90177a0983561882d758959e2022006b4d0848dfd6a677fd2c06e5ab80466e992fa956582013ef901509000000000000000000000000000000000a02c38e0fd45b4eb4a73f7fe12749bd1229dde283399bffabd4e90589c1e561f57b8c0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000010f08ac0c1c6c8f2be528b35824755054000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f7a696f6e5f6c6f636b5f70726f7879000000000000000000000000000000000082013e90f08ac0c1c6c8f2be528b35824755054086756e6c6f636bb83f0d3078313a3a5354433a3a5354431048b75ec5bb72e54bca2633c36ca3eb041027000000000000000000000000000000000000000000000000000000000000\",\"DstChainId\":318,\"DstProxy\":\"f08ac0c1c6c8f2be528b358247550540\",\"ToAssetAddress\":\"0x1::STC::STC\",\"Delay\":0}"
//	tx := json.Unmarshal()
//	coinTypeTag, _ := getAssetCoinTypeTag("0x00000000000000000000000000000001::STC::STC")
//
//	cctx, err := hex.DecodeString(tx.PolyParam)
//	if err != nil || len(cctx) == 0 {
//		return fmt.Errorf("poly param merke value missing or invalid")
//	}
//
//	hsHeader, err := rlp.EncodeToBytes(types.HotstuffFilteredHeader(tx.AnchorHeader))
//	if err != nil {
//		log.Error("EncodeToBytes Hotstuff failed", "polyHash", tx.PolyHash.Hex(), "err", err)
//		return err
//	}
//
//	extra, err := types.ExtractHotstuffExtra(tx.AnchorHeader)
//	if err != nil {
//		log.Error("ExtractHotstuffExtra failed", "polyHash", tx.PolyHash.Hex(), "err", err)
//		return
//	}
//	rawSeals, err := rlp.EncodeToBytes(extra.CommittedSeal)
//	if err != nil {
//		log.Error("rlp.EncodeToBytes failed", "polyHash", tx.PolyHash.Hex(), "err", err)
//		return
//	}
//
//	//seed, err := hex.DecodeString(this.wallet.PrivateKey)
//	//if err != nil {
//	//	return fmt.Errorf("decode private key error: %v", err)
//	//}
//	//priv := ed25519.NewKeyFromSeed(seed)
//	//pub := priv.Public().(ed25519.PublicKey)
//	//authKey := sha3.Sum256(append(pub[:], 0x00))
//	//address := hex.EncodeToString(authKey[:])
//
//	coinTypeTag, err := getAssetCoinTypeTag(tx.ToAssetAddress)
//	if err != nil {
//		return fmt.Errorf("getAssetCoinTypeTag error: %s", err)
//	}
//	log.Info("Before commit relayer transaction from zion, \nhsHeader: %s\n rawSeals: %s\n tx.PolyAccountProof\n tx.PolyStorageProof: %s\n ccctx: %s\n",
//		starcoin_client.BytesToHexString(hsHeader),
//		starcoin_client.BytesToHexString(rawSeals),
//		starcoin_client.BytesToHexString(tx.PolyAccountProof),
//		starcoin_client.BytesToHexString(tx.PolyStorageProof),
//		starcoin_client.BytesToHexString(cctx))
//	log.Info("Coin type tag: ", coinTypeTag)
//}
