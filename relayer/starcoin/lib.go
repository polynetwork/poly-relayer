package starcoin

import (
	"fmt"

	"github.com/novifinancial/serde-reflection/serde-generate/runtime/golang/bcs"
	"github.com/novifinancial/serde-reflection/serde-generate/runtime/golang/serde"
)

type AccountAddress [16]uint8

func (obj *AccountAddress) Serialize(serializer serde.Serializer) error {
	if err := serializer.IncreaseContainerDepth(); err != nil {
		return err
	}
	if err := serialize_array16_u8_array((([16]uint8)(*obj)), serializer); err != nil {
		return err
	}
	serializer.DecreaseContainerDepth()
	return nil
}

func (obj *AccountAddress) BcsSerialize() ([]byte, error) {
	if obj == nil {
		return nil, fmt.Errorf("Cannot serialize null object")
	}
	serializer := bcs.NewSerializer()
	if err := obj.Serialize(serializer); err != nil {
		return nil, err
	}
	return serializer.GetBytes(), nil
}

func DeserializeAccountAddress(deserializer serde.Deserializer) (AccountAddress, error) {
	var obj [16]uint8
	if err := deserializer.IncreaseContainerDepth(); err != nil {
		return (AccountAddress)(obj), err
	}
	if val, err := deserialize_array16_u8_array(deserializer); err == nil {
		obj = val
	} else {
		return ((AccountAddress)(obj)), err
	}
	deserializer.DecreaseContainerDepth()
	return (AccountAddress)(obj), nil
}

func BcsDeserializeAccountAddress(input []byte) (AccountAddress, error) {
	if input == nil {
		var obj AccountAddress
		return obj, fmt.Errorf("Cannot deserialize null array")
	}
	deserializer := bcs.NewDeserializer(input)
	obj, err := DeserializeAccountAddress(deserializer)
	if err == nil && deserializer.GetBufferOffset() < uint64(len(input)) {
		return obj, fmt.Errorf("Some input bytes were not read")
	}
	return obj, err
}

type CrossChainEvent struct {
	Sender               []byte
	TxId                 []byte
	ProxyOrAssetContract []byte
	ToChainId            uint64
	ToContract           []byte
	RawData              []byte
}

func (obj *CrossChainEvent) Serialize(serializer serde.Serializer) error {
	if err := serializer.IncreaseContainerDepth(); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.Sender); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.TxId); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.ProxyOrAssetContract); err != nil {
		return err
	}
	if err := serializer.SerializeU64(obj.ToChainId); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.ToContract); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.RawData); err != nil {
		return err
	}
	serializer.DecreaseContainerDepth()
	return nil
}

func (obj *CrossChainEvent) BcsSerialize() ([]byte, error) {
	if obj == nil {
		return nil, fmt.Errorf("Cannot serialize null object")
	}
	serializer := bcs.NewSerializer()
	if err := obj.Serialize(serializer); err != nil {
		return nil, err
	}
	return serializer.GetBytes(), nil
}

func DeserializeCrossChainEvent(deserializer serde.Deserializer) (CrossChainEvent, error) {
	var obj CrossChainEvent
	if err := deserializer.IncreaseContainerDepth(); err != nil {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.Sender = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.TxId = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.ProxyOrAssetContract = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeU64(); err == nil {
		obj.ToChainId = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.ToContract = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.RawData = val
	} else {
		return obj, err
	}
	deserializer.DecreaseContainerDepth()
	return obj, nil
}

func BcsDeserializeCrossChainEvent(input []byte) (CrossChainEvent, error) {
	if input == nil {
		var obj CrossChainEvent
		return obj, fmt.Errorf("Cannot deserialize null array")
	}
	deserializer := bcs.NewDeserializer(input)
	obj, err := DeserializeCrossChainEvent(deserializer)
	if err == nil && deserializer.GetBufferOffset() < uint64(len(input)) {
		return obj, fmt.Errorf("Some input bytes were not read")
	}
	return obj, err
}

type CrossChainFeeLockEvent struct {
	FromAssetHash TokenCode
	Sender        AccountAddress
	ToChainId     uint64
	ToAddress     []byte
	Net           serde.Uint128
	Fee           serde.Uint128
	Id            serde.Uint128
}

func (obj *CrossChainFeeLockEvent) Serialize(serializer serde.Serializer) error {
	if err := serializer.IncreaseContainerDepth(); err != nil {
		return err
	}
	if err := obj.FromAssetHash.Serialize(serializer); err != nil {
		return err
	}
	if err := obj.Sender.Serialize(serializer); err != nil {
		return err
	}
	if err := serializer.SerializeU64(obj.ToChainId); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.ToAddress); err != nil {
		return err
	}
	if err := serializer.SerializeU128(obj.Net); err != nil {
		return err
	}
	if err := serializer.SerializeU128(obj.Fee); err != nil {
		return err
	}
	if err := serializer.SerializeU128(obj.Id); err != nil {
		return err
	}
	serializer.DecreaseContainerDepth()
	return nil
}

func (obj *CrossChainFeeLockEvent) BcsSerialize() ([]byte, error) {
	if obj == nil {
		return nil, fmt.Errorf("Cannot serialize null object")
	}
	serializer := bcs.NewSerializer()
	if err := obj.Serialize(serializer); err != nil {
		return nil, err
	}
	return serializer.GetBytes(), nil
}

func DeserializeCrossChainFeeLockEvent(deserializer serde.Deserializer) (CrossChainFeeLockEvent, error) {
	var obj CrossChainFeeLockEvent
	if err := deserializer.IncreaseContainerDepth(); err != nil {
		return obj, err
	}
	if val, err := DeserializeTokenCode(deserializer); err == nil {
		obj.FromAssetHash = val
	} else {
		return obj, err
	}
	if val, err := DeserializeAccountAddress(deserializer); err == nil {
		obj.Sender = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeU64(); err == nil {
		obj.ToChainId = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.ToAddress = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeU128(); err == nil {
		obj.Net = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeU128(); err == nil {
		obj.Fee = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeU128(); err == nil {
		obj.Id = val
	} else {
		return obj, err
	}
	deserializer.DecreaseContainerDepth()
	return obj, nil
}

func BcsDeserializeCrossChainFeeLockEvent(input []byte) (CrossChainFeeLockEvent, error) {
	if input == nil {
		var obj CrossChainFeeLockEvent
		return obj, fmt.Errorf("Cannot deserialize null array")
	}
	deserializer := bcs.NewDeserializer(input)
	obj, err := DeserializeCrossChainFeeLockEvent(deserializer)
	if err == nil && deserializer.GetBufferOffset() < uint64(len(input)) {
		return obj, fmt.Errorf("Some input bytes were not read")
	}
	return obj, err
}

type CrossChainFeeSpeedUpEvent struct {
	FromAssetHash TokenCode
	Sender        AccountAddress
	TxHash        []byte
	Efee          serde.Uint128
}

func (obj *CrossChainFeeSpeedUpEvent) Serialize(serializer serde.Serializer) error {
	if err := serializer.IncreaseContainerDepth(); err != nil {
		return err
	}
	if err := obj.FromAssetHash.Serialize(serializer); err != nil {
		return err
	}
	if err := obj.Sender.Serialize(serializer); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.TxHash); err != nil {
		return err
	}
	if err := serializer.SerializeU128(obj.Efee); err != nil {
		return err
	}
	serializer.DecreaseContainerDepth()
	return nil
}

func (obj *CrossChainFeeSpeedUpEvent) BcsSerialize() ([]byte, error) {
	if obj == nil {
		return nil, fmt.Errorf("Cannot serialize null object")
	}
	serializer := bcs.NewSerializer()
	if err := obj.Serialize(serializer); err != nil {
		return nil, err
	}
	return serializer.GetBytes(), nil
}

func DeserializeCrossChainFeeSpeedUpEvent(deserializer serde.Deserializer) (CrossChainFeeSpeedUpEvent, error) {
	var obj CrossChainFeeSpeedUpEvent
	if err := deserializer.IncreaseContainerDepth(); err != nil {
		return obj, err
	}
	if val, err := DeserializeTokenCode(deserializer); err == nil {
		obj.FromAssetHash = val
	} else {
		return obj, err
	}
	if val, err := DeserializeAccountAddress(deserializer); err == nil {
		obj.Sender = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.TxHash = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeU128(); err == nil {
		obj.Efee = val
	} else {
		return obj, err
	}
	deserializer.DecreaseContainerDepth()
	return obj, nil
}

func BcsDeserializeCrossChainFeeSpeedUpEvent(input []byte) (CrossChainFeeSpeedUpEvent, error) {
	if input == nil {
		var obj CrossChainFeeSpeedUpEvent
		return obj, fmt.Errorf("Cannot deserialize null array")
	}
	deserializer := bcs.NewDeserializer(input)
	obj, err := DeserializeCrossChainFeeSpeedUpEvent(deserializer)
	if err == nil && deserializer.GetBufferOffset() < uint64(len(input)) {
		return obj, fmt.Errorf("Some input bytes were not read")
	}
	return obj, err
}

type LockEvent struct {
	FromAssetHash TokenCode
	FromAddress   []byte
	ToChainId     uint64
	ToAssetHash   []byte
	ToAddress     []byte
	Amount        serde.Uint128
}

func (obj *LockEvent) Serialize(serializer serde.Serializer) error {
	if err := serializer.IncreaseContainerDepth(); err != nil {
		return err
	}
	if err := obj.FromAssetHash.Serialize(serializer); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.FromAddress); err != nil {
		return err
	}
	if err := serializer.SerializeU64(obj.ToChainId); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.ToAssetHash); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.ToAddress); err != nil {
		return err
	}
	if err := serializer.SerializeU128(obj.Amount); err != nil {
		return err
	}
	serializer.DecreaseContainerDepth()
	return nil
}

func (obj *LockEvent) BcsSerialize() ([]byte, error) {
	if obj == nil {
		return nil, fmt.Errorf("Cannot serialize null object")
	}
	serializer := bcs.NewSerializer()
	if err := obj.Serialize(serializer); err != nil {
		return nil, err
	}
	return serializer.GetBytes(), nil
}

func DeserializeLockEvent(deserializer serde.Deserializer) (LockEvent, error) {
	var obj LockEvent
	if err := deserializer.IncreaseContainerDepth(); err != nil {
		return obj, err
	}
	if val, err := DeserializeTokenCode(deserializer); err == nil {
		obj.FromAssetHash = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.FromAddress = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeU64(); err == nil {
		obj.ToChainId = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.ToAssetHash = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.ToAddress = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeU128(); err == nil {
		obj.Amount = val
	} else {
		return obj, err
	}
	deserializer.DecreaseContainerDepth()
	return obj, nil
}

func BcsDeserializeLockEvent(input []byte) (LockEvent, error) {
	if input == nil {
		var obj LockEvent
		return obj, fmt.Errorf("Cannot deserialize null array")
	}
	deserializer := bcs.NewDeserializer(input)
	obj, err := DeserializeLockEvent(deserializer)
	if err == nil && deserializer.GetBufferOffset() < uint64(len(input)) {
		return obj, fmt.Errorf("Some input bytes were not read")
	}
	return obj, err
}

type TokenCode struct {
	Address AccountAddress
	Module  string
	Name    string
}

func (obj *TokenCode) Serialize(serializer serde.Serializer) error {
	if err := serializer.IncreaseContainerDepth(); err != nil {
		return err
	}
	if err := obj.Address.Serialize(serializer); err != nil {
		return err
	}
	if err := serializer.SerializeStr(obj.Module); err != nil {
		return err
	}
	if err := serializer.SerializeStr(obj.Name); err != nil {
		return err
	}
	serializer.DecreaseContainerDepth()
	return nil
}

func (obj *TokenCode) BcsSerialize() ([]byte, error) {
	if obj == nil {
		return nil, fmt.Errorf("Cannot serialize null object")
	}
	serializer := bcs.NewSerializer()
	if err := obj.Serialize(serializer); err != nil {
		return nil, err
	}
	return serializer.GetBytes(), nil
}

func DeserializeTokenCode(deserializer serde.Deserializer) (TokenCode, error) {
	var obj TokenCode
	if err := deserializer.IncreaseContainerDepth(); err != nil {
		return obj, err
	}
	if val, err := DeserializeAccountAddress(deserializer); err == nil {
		obj.Address = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeStr(); err == nil {
		obj.Module = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeStr(); err == nil {
		obj.Name = val
	} else {
		return obj, err
	}
	deserializer.DecreaseContainerDepth()
	return obj, nil
}

func BcsDeserializeTokenCode(input []byte) (TokenCode, error) {
	if input == nil {
		var obj TokenCode
		return obj, fmt.Errorf("Cannot deserialize null array")
	}
	deserializer := bcs.NewDeserializer(input)
	obj, err := DeserializeTokenCode(deserializer)
	if err == nil && deserializer.GetBufferOffset() < uint64(len(input)) {
		return obj, fmt.Errorf("Some input bytes were not read")
	}
	return obj, err
}

type UnlockEvent struct {
	ToAssetHash []byte
	ToAddress   []byte
	Amount      serde.Uint128
}

func (obj *UnlockEvent) Serialize(serializer serde.Serializer) error {
	if err := serializer.IncreaseContainerDepth(); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.ToAssetHash); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.ToAddress); err != nil {
		return err
	}
	if err := serializer.SerializeU128(obj.Amount); err != nil {
		return err
	}
	serializer.DecreaseContainerDepth()
	return nil
}

func (obj *UnlockEvent) BcsSerialize() ([]byte, error) {
	if obj == nil {
		return nil, fmt.Errorf("Cannot serialize null object")
	}
	serializer := bcs.NewSerializer()
	if err := obj.Serialize(serializer); err != nil {
		return nil, err
	}
	return serializer.GetBytes(), nil
}

func DeserializeUnlockEvent(deserializer serde.Deserializer) (UnlockEvent, error) {
	var obj UnlockEvent
	if err := deserializer.IncreaseContainerDepth(); err != nil {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.ToAssetHash = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.ToAddress = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeU128(); err == nil {
		obj.Amount = val
	} else {
		return obj, err
	}
	deserializer.DecreaseContainerDepth()
	return obj, nil
}

func BcsDeserializeUnlockEvent(input []byte) (UnlockEvent, error) {
	if input == nil {
		var obj UnlockEvent
		return obj, fmt.Errorf("Cannot deserialize null array")
	}
	deserializer := bcs.NewDeserializer(input)
	obj, err := DeserializeUnlockEvent(deserializer)
	if err == nil && deserializer.GetBufferOffset() < uint64(len(input)) {
		return obj, fmt.Errorf("Some input bytes were not read")
	}
	return obj, err
}

type VerifyHeaderAndExecuteTxEvent struct {
	FromChainId      uint64
	ToContract       []byte
	CrossChainTxHash []byte
	FromChainTxHash  []byte
}

func (obj *VerifyHeaderAndExecuteTxEvent) Serialize(serializer serde.Serializer) error {
	if err := serializer.IncreaseContainerDepth(); err != nil {
		return err
	}
	if err := serializer.SerializeU64(obj.FromChainId); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.ToContract); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.CrossChainTxHash); err != nil {
		return err
	}
	if err := serializer.SerializeBytes(obj.FromChainTxHash); err != nil {
		return err
	}
	serializer.DecreaseContainerDepth()
	return nil
}

func (obj *VerifyHeaderAndExecuteTxEvent) BcsSerialize() ([]byte, error) {
	if obj == nil {
		return nil, fmt.Errorf("Cannot serialize null object")
	}
	serializer := bcs.NewSerializer()
	if err := obj.Serialize(serializer); err != nil {
		return nil, err
	}
	return serializer.GetBytes(), nil
}

func DeserializeVerifyHeaderAndExecuteTxEvent(deserializer serde.Deserializer) (VerifyHeaderAndExecuteTxEvent, error) {
	var obj VerifyHeaderAndExecuteTxEvent
	if err := deserializer.IncreaseContainerDepth(); err != nil {
		return obj, err
	}
	if val, err := deserializer.DeserializeU64(); err == nil {
		obj.FromChainId = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.ToContract = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.CrossChainTxHash = val
	} else {
		return obj, err
	}
	if val, err := deserializer.DeserializeBytes(); err == nil {
		obj.FromChainTxHash = val
	} else {
		return obj, err
	}
	deserializer.DecreaseContainerDepth()
	return obj, nil
}

func BcsDeserializeVerifyHeaderAndExecuteTxEvent(input []byte) (VerifyHeaderAndExecuteTxEvent, error) {
	if input == nil {
		var obj VerifyHeaderAndExecuteTxEvent
		return obj, fmt.Errorf("Cannot deserialize null array")
	}
	deserializer := bcs.NewDeserializer(input)
	obj, err := DeserializeVerifyHeaderAndExecuteTxEvent(deserializer)
	if err == nil && deserializer.GetBufferOffset() < uint64(len(input)) {
		return obj, fmt.Errorf("Some input bytes were not read")
	}
	return obj, err
}
func serialize_array16_u8_array(value [16]uint8, serializer serde.Serializer) error {
	for _, item := range value {
		if err := serializer.SerializeU8(item); err != nil {
			return err
		}
	}
	return nil
}

func deserialize_array16_u8_array(deserializer serde.Deserializer) ([16]uint8, error) {
	var obj [16]uint8
	for i := range obj {
		if val, err := deserializer.DeserializeU8(); err == nil {
			obj[i] = val
		} else {
			return obj, err
		}
	}
	return obj, nil
}
