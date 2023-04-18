package starcoin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/sm2"
)

// encode big int to hex string
func EncodeBigInt(b *big.Int) string {
	if b.Uint64() == 0 {
		return "00"
	}
	return hex.EncodeToString(b.Bytes())
}

// encode bytes to hex with prefix
func EncodeToHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

func HexWithPrefixToBytes(str string) ([]byte, error) {
	if !strings.HasPrefix(str, "0x") {
		return nil, fmt.Errorf("it does not have 0x prefix")
	}
	return hex.DecodeString(str[2:])
}

func HexToBytes(str string) ([]byte, error) {
	if !strings.HasPrefix(str, "0x") {
		return hex.DecodeString(str[:])
	}
	return hex.DecodeString(str[2:])
}

func CurrentTimeMillis() int64 {
	return time.Now().UnixNano() / 1000000
}

const (
	STARCOIN_CHAIN_ID_MAIN    int = 1
	STARCOIN_CHAIN_ID_BARNARD int = 251
	STARCOIN_CHAIN_ID_PROXIMA int = 252
	STARCOIN_CHAIN_ID_HALLEY  int = 253
)

// Get Starcoin explorer Txn. URL
func GetExplorerUrl(chainId int) string {
	switch chainId {
	case STARCOIN_CHAIN_ID_MAIN:
		return "https://stcscan.io/main/transactions/detail/"
	case STARCOIN_CHAIN_ID_BARNARD:
		return "https://stcscan.io/barnard/transactions/detail/"
	case STARCOIN_CHAIN_ID_PROXIMA:
		return "https://stcscan.io/proxima/transactions/detail/"
	case STARCOIN_CHAIN_ID_HALLEY:
		return "https://stcscan.io/halley/transactions/detail/"
	default:
		return "{NO-URL}/"
	}
}

func GetNoCompresskey(key keypair.PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == elliptic.P256().Params().Name {
				return ec.EncodePublicKey(t.PublicKey, false)
			}
			buf.WriteByte(byte(0x12))
		case ec.SM2:
			buf.WriteByte(byte(0x13))
		}
		label, err := GetCurveLabel(t.Curve.Params().Name)
		if err != nil {
			panic(err)
		}
		buf.WriteByte(label)
		buf.Write(ec.EncodePublicKey(t.PublicKey, false))
	case ed25519.PublicKey:
		panic("err")
	default:
		panic("err")
	}
	return buf.Bytes()
}

func GetCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(elliptic.P224().Params().Name):
		return 1, nil
	case strings.ToUpper(elliptic.P256().Params().Name):
		return 2, nil
	case strings.ToUpper(elliptic.P384().Params().Name):
		return 3, nil
	case strings.ToUpper(elliptic.P521().Params().Name):
		return 4, nil
	case strings.ToUpper(sm2.SM2P256V1().Params().Name):
		return 20, nil
	case strings.ToUpper(btcec.S256().Name):
		return 5, nil
	default:
		panic("err")
	}
}

func GetEthNoCompressKey(key keypair.PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		return crypto.FromECDSAPub(t.PublicKey)
	case ed25519.PublicKey:
		panic("err")
	default:
		panic("err")
	}
	return buf.Bytes()
}
