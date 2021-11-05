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
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/sm2"

	ccom "github.com/devfans/zion-sdk/contracts/native/cross_chain_manager/common"
	"github.com/devfans/zion-sdk/contracts/native/governance/node_manager"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains/bridge"
	pcom "github.com/polynetwork/poly/common"
)

var TxParam abi.Arguments

func init() {
	BytesTy, _ := abi.NewType("bytes", "", nil)
	IntTy, _ := abi.NewType("int", "", nil)
	StringTy, _ := abi.NewType("string", "", nil)

	TxParam = abi.Arguments{
		{Type: BytesTy, Name: "txHash"},
		{Type: BytesTy, Name: "crossChainID"},
		{Type: BytesTy, Name: "fromContractAddress"},
		{Type: IntTy, Name: "toChainID"},
		{Type: BytesTy, Name: "toContractAddress"},
		{Type: StringTy, Name: "method"},
		{Type: BytesTy, Name: "args"},
	}
}

type Message interface {
	Type() TxType
	Encode() string
	Decode(string) error
}

type TxType int

const (
	SRC        TxType = 1
	POLY       TxType = 2
	HEADER     TxType = 3
	POLY_EPOCH TxType = 4
)

type Header struct {
	Height uint64
	Hash   []byte
	Data   []byte
}

type PolyEpoch struct {
	Height          uint64
	EpochId         uint64
	HeaderHex       string `json:",omitempty"`
	SealHex         string `json:",omitempty"`
	AccountProofHex string `json:",omitempty"`
	StorageProofHex string `json:",omitempty"`
	EpochHex        string `json:",omitempty"`
	Header          []byte `json:"-"`
	Seal            []byte `json:"-"`
	AccountProof    []byte `json:"-"`
	StorageProof    []byte `json:"-"`
	Epoch           []byte `json:"-"`
}

func RlpEncodeEpoch(id, startHeight uint64, peers *node_manager.Peers) (bytes []byte, err error) {
	return rlp.EncodeToBytes(
		struct {
			ID          uint64
			Peers       *node_manager.Peers
			StartHeight uint64
		}{
			ID:          id,
			Peers:       peers,
			StartHeight: startHeight,
		},
	)
}

func (m *PolyEpoch) Encode() {
	m.HeaderHex = hex.EncodeToString(m.Header)
	m.SealHex = hex.EncodeToString(m.Seal)
	m.AccountProofHex = hex.EncodeToString(m.AccountProof)
	m.StorageProofHex = hex.EncodeToString(m.StorageProof)
	m.EpochHex = hex.EncodeToString(m.Epoch)
}

func (m *PolyEpoch) Decode() {
	m.Header, _ = hex.DecodeString(m.HeaderHex)
	m.Seal, _ = hex.DecodeString(m.SealHex)
	m.AccountProof, _ = hex.DecodeString(m.AccountProofHex)
	m.StorageProof, _ = hex.DecodeString(m.StorageProofHex)
	m.Epoch, _ = hex.DecodeString(m.EpochHex)
}

type PolyComposer func(*Tx) error

type Tx struct {
	TxType   TxType
	Attempts int

	TxId        string              `json:",omitempty"`
	MerkleValue *ccom.ToMerkleValue `json:"-"`
	Param       *ccom.MakeTxParam   `json:"-"`

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

	PolyHash         common.Hash   `json:",omitempty"`
	PolyHeight       uint64        `json:",omitempty"`
	PolyKey          string        `json:",omitempty"`
	PolyHeader       *types.Header `json:"-"`
	AnchorHeader     *types.Header `json:"-"`
	AnchorHeight     uint64        `json:",omitempty"`
	PolySigs         []byte        `json:"-"`
	PolySender       interface{}   `json:"-"`
	PolyData         []byte        `json:"-"`
	PolyParam        string        `json:",omitempty"`
	PolyAccountProof []byte        `json:"-"`
	PolyStorageProof []byte        `json:"-"`
	PolyEpoch        *PolyEpoch    `json:",omitempty"`

	DstHash                 string                `json:",omitempty"`
	DstHeight               uint64                `json:",omitempty"`
	DstChainId              uint64                `json:",omitempty"`
	DstGasLimit             uint64                `json:",omitempty"`
	DstGasPrice             string                `json:",omitempty"`
	DstGasPriceX            string                `json:",omitempty"`
	DstSender               interface{}           `json:"-"`
	DstPolyEpochStartHeight uint64                `json:",omitempty"`
	DstPolyKeepers          []byte                `json:"-"`
	DstData                 []byte                `json:"-"`
	DstProxy                string                `json:",omitempty"`
	SkipCheckFee            bool                  `json:",omitempty"`
	Skipped                 bool                  `json:",omitempty"`
	CheckFeeStatus          bridge.CheckFeeStatus `json:",omitempty"`
}

func (tx *Tx) Type() TxType {
	return tx.TxType
}

func Hash(str string) common.Hash {
	return common.HexToHash(str)
}

func Empty(hash common.Hash) bool {
	return hash == common.Hash{}
}

func (tx *Tx) Encode() string {
	if len(tx.SrcProof) > 0 && len(tx.SrcProofHex) == 0 {
		tx.SrcProofHex = hex.EncodeToString(tx.SrcProof)
	}
	bytes, _ := json.Marshal(*tx)
	return string(bytes)
}

type MakeTxParamShim struct {
	TxHash              []byte
	CrossChainID        []byte
	FromContractAddress []byte
	ToChainID           *big.Int
	ToContractAddress   []byte
	Method              string
	Args                []byte
}

func DecodeTxParam(data []byte) (param *ccom.MakeTxParam, err error) {
	args, err := TxParam.Unpack(data)
	if err != nil {
		return
	}

	shim := new(MakeTxParamShim)
	err = TxParam.Copy(param, args)
	if err != nil {
		return nil, err
	}
	param = &ccom.MakeTxParam{
		TxHash:              shim.TxHash,
		CrossChainID:        shim.CrossChainID,
		ToChainID:           shim.ToChainID.Uint64(),
		FromContractAddress: shim.FromContractAddress,
		ToContractAddress:   shim.ToContractAddress,
		Method:              shim.Method,
		Args:                shim.Args,
	}
	return
}

func (tx *Tx) Decode(data string) (err error) {
	err = json.Unmarshal([]byte(data), tx)
	if err == nil {
		if len(tx.SrcParam) > 0 && tx.Param == nil {
			event, err := hex.DecodeString(tx.SrcParam)
			if err != nil {
				return fmt.Errorf("Decode src param error %v event %s", err, tx.SrcParam)
			}
			param := &ccom.MakeTxParam{}
			err = param.Deserialization(pcom.NewZeroCopySource(event))
			if err != nil {
				return fmt.Errorf("Decode src event error %v event %s", err, tx.SrcParam)
			}
			tx.Param = param
			tx.SrcEvent = event
		}
		if len(tx.PolyParam) > 0 && tx.Param == nil {
			param := new(ccom.ToMerkleValue)
			value, err := hex.DecodeString(tx.PolyParam)
			if err != nil {
				return fmt.Errorf("Decode poly param error %v event %s", err, tx.PolyParam)
			}
			tx.MerkleValue = param
			err = param.Deserialization(pcom.NewZeroCopySource(value))
			if err != nil {
				return fmt.Errorf("Decode poly merkle value error %v", err)
			}
			tx.Param = tx.MerkleValue.MakeTxParam
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

func RlpEncodeStrings(strs []string) ([]byte, error) {
	var bytes []byte
	for _, str := range strs {
		bytes = append(bytes, common.Hex2Bytes(str[2:])...)
	}
	return rlp.EncodeToBytes(bytes)
}
