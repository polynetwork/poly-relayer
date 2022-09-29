package msg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/sm2"

	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/bridge"
	pcom "github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	"github.com/polynetwork/poly/native/service/cross_chain_manager/common"
)

type Message interface {
	Type() TxType
	Encode() string
	Decode(string) error
}

type TxType int

const (
	SRC    TxType = 1
	POLY   TxType = 2
	HEADER TxType = 3
)

type Header struct {
	Height uint64
	Hash   []byte
	Data   []byte
}

type PolyComposer func(*Tx) error
type SrcComposer interface {
	Compose(*Tx) error
	LatestHeight() (uint64, error)
}

type Tx struct {
	TxType   TxType
	Attempts int

	TxId        string                `json:",omitempty"`
	MerkleValue *common.ToMerkleValue `json:"-"`
	Param       *common.MakeTxParam   `json:"-"`

	SrcHash        string `json:",omitempty"`
	SrcHeight      uint64 `json:",omitempty"`
	SrcChainId     uint64 `json:",omitempty"`
	SrcProof       []byte `json:"-"`
	SrcProofHex    string `json:",omitempty"`
	SrcEvent       []byte `json:"-"`
	SrcProofHeight uint64 `json:",omitempty"`
	SrcParam       string `json:",omitempty"`
	SrcStateRoot   []byte `json:"-"`
	SrcProxy       string `json:",omitempty"`
	SrcAddress     string `json:",omitempty"`

	PolyHash     string        `json:",omitempty"`
	PolyHeight   uint32        `json:",omitempty"`
	PolyKey      string        `json:",omitempty"`
	PolyHeader   *types.Header `json:"-"`
	AnchorHeader *types.Header `json:"-"`
	AnchorProof  string        `json:",omitempty"`
	AuditPath    string        `json:"-"`
	PolySigs     []byte        `json:"-"`

	DstAddress              string                `json:",omitempty"`
	DstHash                 string                `json:",omitempty"`
	DstHeight               uint64                `json:",omitempty"`
	DstChainId              uint64                `json:",omitempty"`
	DstGasLimit             uint64                `json:",omitempty"`
	DstGasPrice             string                `json:",omitempty"`
	DstGasPriceX            string                `json:",omitempty"`
	DstSender               interface{}           `json:"-"`
	DstPolyEpochStartHeight uint32                `json:",omitempty"`
	DstPolyKeepers          []byte                `json:"-"`
	DstData                 []byte                `json:"-"`
	DstProxy                string                `json:",omitempty"`
	SkipCheckFee            bool                  `json:",omitempty"`
	CheckFeeOff             bool                  `json:"-"` // CheckFee disabled in submitter
	Skipped                 bool                  `json:",omitempty"`
	PaidGas                 float64               `json:",omitempty"`
	CheckFeeStatus          bridge.CheckFeeStatus `json:",omitempty"`
	DstAsset                string                `json:"-"`
	DstAmount               *big.Int              `json:"-"`

	// aptos
	ToAssetAddress string

	Extra interface{} `json:"-"`
}

func (tx *Tx) Type() TxType {
	return tx.TxType
}

func (tx *Tx) Encode() string {
	if len(tx.SrcProof) > 0 && len(tx.SrcProofHex) == 0 {
		tx.SrcProofHex = hex.EncodeToString(tx.SrcProof)
	}
	bytes, _ := json.Marshal(*tx)
	return string(bytes)
}

func (tx *Tx) Decode(data string) (err error) {
	err = json.Unmarshal([]byte(data), tx)
	if err == nil {
		if len(tx.SrcParam) > 0 && tx.Param == nil {
			event, err := hex.DecodeString(tx.SrcParam)
			if err != nil {
				return fmt.Errorf("Decode src param error %v event %s", err, tx.SrcParam)
			}
			param := &common.MakeTxParam{}
			err = param.Deserialization(pcom.NewZeroCopySource(event))
			if err != nil {
				return fmt.Errorf("Decode src event error %v event %s", err, tx.SrcParam)
			}
			tx.Param = param
			tx.SrcEvent = event
		}
	}
	return
}

func (tx *Tx) CapturePatchParams(o *Tx) *Tx {
	if o != nil {
		if o.DstGasLimit > 0 {
			tx.DstGasLimit = o.DstGasLimit
		}
		if len(o.DstGasPrice) > 0 {
			tx.DstGasPrice = o.DstGasPrice
		}

		if len(o.DstGasPriceX) > 0 {
			tx.DstGasPriceX = o.DstGasPriceX
		}

		if o.SkipCheckFee {
			tx.SkipCheckFee = o.SkipCheckFee
		}
		if o.DstSender != nil {
			tx.DstSender = o.DstSender
		}
	}
	return tx
}

func (tx *Tx) SkipFee() bool {
	if tx.SkipCheckFee {
		return true
	}
	switch tx.DstChainId {
	case base.PLT, base.O3:
		return true
	}
	return false
}

func (tx *Tx) GetTxId() (id [32]byte, err error) {
	bytes, err := hex.DecodeString(tx.TxId)
	if err != nil {
		err = fmt.Errorf("GetTxId Invalid tx id hex %v", err)
		return
	}
	copy(id[:], bytes[:32])
	return
}

func EncodeEthPubKey(key keypair.PublicKey) ([]byte, error) {
	switch t := key.(type) {
	case *ec.PublicKey:
		return crypto.FromECDSAPub(t.PublicKey), nil
	case ed25519.PublicKey:
		return nil, fmt.Errorf("EncodeEthPubKey: ed25519.PublicKey?")
	default:
		return nil, fmt.Errorf("EncodeEthPubKey: Unkown key type?")
	}
}

func EncodePubKey(key keypair.PublicKey) ([]byte, error) {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == elliptic.P256().Params().Name {
				return ec.EncodePublicKey(t.PublicKey, false), nil
			}
			buf.WriteByte(byte(0x12))
		case ec.SM2:
			buf.WriteByte(byte(0x13))
		}
		label, err := GetCurveLabel(t.Curve.Params().Name)
		if err != nil {
			return nil, fmt.Errorf("EncodePubKey %v", err)
		}
		buf.WriteByte(label)
		buf.Write(ec.EncodePublicKey(t.PublicKey, false))
	case ed25519.PublicKey:
		return nil, fmt.Errorf("EncodePubKey: ed25519.PublicKey?")
	default:
		return nil, fmt.Errorf("EncodePubKey: unknown key type")
	}
	return buf.Bytes(), nil
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
		return 0, fmt.Errorf("GetCurveLabel: unknown labelname %s", name)
	}
}

func ParseAuditPath(path []byte) (value []byte, pos []byte, hashes [][32]byte, err error) {
	source := pcom.NewZeroCopySource(path)
	value, eof := source.NextVarBytes()
	if eof {
		return
	}
	size := int((source.Size() - source.Pos()) / pcom.UINT256_SIZE)
	pos = []byte{}
	hashes = [][32]byte{}
	for i := 0; i < size; i++ {
		f, eof := source.NextByte()
		if eof {
			return
		}
		pos = append(pos, f)

		v, eof := source.NextHash()
		if eof {
			return
		}
		var hash [32]byte
		copy(hash[:], v.ToArray()[0:32])
		hashes = append(hashes, hash)
	}
	return
}

func EncodeTxId(id []byte) string {
	index := big.NewInt(0)
	index.SetBytes(id)
	if index.Uint64() == 0 {
		return "00"
	}
	return hex.EncodeToString(index.Bytes())
}
