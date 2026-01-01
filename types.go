package tlv

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"reflect"
)

func NewFromFrame(frame TLVFrame, opts ...FrameOption) (*TlV, error) {
	option := newOption(opts...)
	tag, data, err := tlv_decode_opt(frame, option)
	if err != nil {
		return nil, err
	}
	return &TlV{T: tag, L: uint16(len(data)), V: data}, nil
}

func EmptyFrame(opts ...FrameOption) TLVFrame {
	option := newOption(opts...)
	return tlv_empty_frame(option)
}

func FrameFromString(v string, opts ...FrameOption) TLVFrame {
	option := newOption(opts...)
	_, err := tlv_encode_option_with_buffer(TLV_TYPE_STRING, []byte(v), option)
	if err != nil {
		return []byte{}
	}
	return option.Bytes()
}

func FrameFromJson(v any, opts ...FrameOption) TLVFrame {
	option := newOption(opts...)
	jsonData, err := json.Marshal(v)
	if err != nil {
		return []byte{}
	}
	_, err = tlv_encode_option_with_buffer(TLV_TYPE_JSON, jsonData, option)
	if err != nil {
		return []byte{}
	}
	return option.Bytes()
}

// Float64 从float64编码为tlv
func FrameFromFloat64(v float64, opts ...FrameOption) TLVFrame {
	option := newOption(opts...)
	bits := math.Float64bits(v)
	bytes := make([]byte, 8+option.MinLength+1)
	binary.BigEndian.PutUint64(bytes[option.MinLength+1:], bits)
	_, err := tlv_encode_option_with_buffer(TLV_TYPE_FLOAT64, bytes, option)
	if err != nil {
		return []byte{}
	}
	return option.Bytes()

}

// Int64 从int64编码为tlv
func FrameFromInt64(v int64, opts ...FrameOption) TLVFrame {
	option := newOption(opts...)
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, uint64(v))
	_, err := tlv_encode_option_with_buffer(TLV_TYPE_INT64, bytes, option)
	if err != nil {
		return []byte{}
	}
	return option.Bytes()
}

// Byte 从byte编码为tlv
func FrameFromByte(v byte, opts ...FrameOption) TLVFrame {
	option := newOption(opts...)
	bytes := make([]byte, 1)
	bytes[0] = v
	_, err := tlv_encode_option_with_buffer(TLV_TYPE_UINT8, bytes, option)
	if err != nil {
		return []byte{}
	}
	return option.Bytes()
}

// Nil 从nil编码为tlv
func FrameFromNil(opts ...FrameOption) TLVFrame {
	option := newOption(opts...)
	tlv_frame_from_nil(option)
	return option.Bytes()
}

// Uint64 从uint64编码为tlv
func FrameFromUint64(v uint64, opts ...FrameOption) TLVFrame {
	option := newOption(opts...)
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, v)
	_, err := tlv_encode_option_with_buffer(TLV_TYPE_UINT64, bytes, option)
	if err != nil {
		return []byte{}
	}
	return option.Bytes()
}

func Bytes2Float64(v []byte) float64 {
	bits := binary.BigEndian.Uint64(v)
	return math.Float64frombits(bits)
}

func FrameToFloat64(v TLVFrame) (float64, error) {
	if len(v) != 8+TLVX_HEADER_SIZE {
		return 0, ErrInvalidFloat64
	}
	if v[0] != TLV_TYPE_FLOAT64 {
		return 0, ErrInvalidFloat64Type
	}
	fv := Bytes2Float64(v[TLVX_HEADER_SIZE:])
	return fv, nil
}

func Bytes2Int64(v []byte) int64 {
	return int64(binary.BigEndian.Uint64(v))
}

func FrameToInt64(v TLVFrame) (int64, error) {
	if len(v) != 8+TLVX_HEADER_SIZE {
		return 0, ErrInvalidInt64
	}
	if v[0] != TLV_TYPE_INT64 {
		return 0, ErrInvalidInt64Type
	}
	bits := Bytes2Uint64(v[TLVX_HEADER_SIZE:])
	return int64(bits), nil
}

func Bytes2Uint64(v []byte) uint64 {
	return binary.BigEndian.Uint64(v)
}

func FrameToUint64(v TLVFrame) (uint64, error) {
	if len(v) != 8+TLVX_HEADER_SIZE {
		return 0, ErrInvalidUint64
	}
	if v[0] != TLV_TYPE_UINT64 {
		return 0, ErrInvalidUint64Type
	}
	bits := Bytes2Uint64(v[TLVX_HEADER_SIZE:])
	return bits, nil
}

// Int64 从int64编码为tlv
func FrameToStruct(v TLVFrame, t any, opts ...FrameOption) error {
	if v == nil {
		return ErrInvalidValueLength
	}
	if len(v) < TLVX_HEADER_SIZE {
		return ErrInvalidValueLength
	}

	option := newOption(opts...)
	_, data, err := tlv_decode_opt(v, option)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, t)
	if err != nil {
		return err
	}
	return nil
}

func FrameToBin(v TLVFrame, opts ...FrameOption) (Bin, error) {
	if v == nil {
		return nil, ErrInvalidValueLength
	}
	if len(v) < TLVX_HEADER_SIZE {
		return nil, ErrInvalidValueLength
	}

	option := newOption(opts...)
	_, _, data, err := tlv_decode_with_len(v, option)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func Deserialize(v []byte, opts ...FrameOption) (*TlV, error) {
	if v == nil {
		return nil, ErrInvalidValueLength
	}
	if len(v) < TLVX_HEADER_MIN_SIZE {
		return nil, ErrInvalidValueLength
	}
	newOpt := newOption(opts...)
	tlv, err := tlv_new_from_frame(v, newOpt)
	if tlv == nil {
		return nil, err
	}
	return tlv, nil
}

// Unmarshal 从tlv解码为结构体
func Json2Struct(v []byte, t any, opts ...FrameOption) error {
	option := newOption(opts...)
	tlv, err := tlv_deserialize(v, option)
	if err != nil {
		return err
	}
	err = json.Unmarshal(tlv.Value(), t)
	if err != nil {
		return err
	}
	return nil
}

// Marshal 从结构体编码为tlv
func Json(v any, opts ...FrameOption) []byte {
	return FrameFromJson(v, opts...)
}

func Serialize(v any, opts ...FrameOption) []byte {
	newOpt := newOption(opts...)
	tlv_serialize_value(reflect.ValueOf(v), newOpt)
	return newOpt.Bytes()
}

// DefaultEncoder is the default encoder.
func DefaultEncoder(v any) ([]byte, error) {
	return Serialize(v), nil
}

// DefaultDecoder is the default decoder.
func DefaultDecoder(data []byte) ([]byte, error) {
	// 空数据
	newOpt := newOption()
	_, data, err := tlv_decode_opt(data, newOpt)
	if err != nil {
		return data, err
	}
	return data, nil
}

func GetType(needPtr bool, name string, data []byte) reflect.Value {
	// []string{"int", "int32", "int64", "uint", "uint32", "uint64", "float32", "float64", "string", "uint8", "bool"}
	switch name {
	case "int":
		by := bytes_to_int(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "int16":
		by := bytes_to_int16(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "int32":
		by := bytes_to_int32(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "int64":
		by := bytes_to_int64(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "uint":
		by := bytes_to_uint(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "uint16":
		by := bytes_to_uint16(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "uint32":
		by := bytes_to_uint32(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "uint64":
		by := bytes_to_uint64(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "float32":
		by := bytes_to_float32(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "float64":
		by := bytes_to_float64(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "string":
		str := string(data)
		if needPtr {
			return reflect.ValueOf(&str)
		}
		return reflect.ValueOf(str)
	case "uint8":
		by := data[0]
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "int8":
		by := int8(data[0])
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "uintptr":
		by := bytes_to_uintptr(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case "bool":
		by := bytes_to_bool(data)
		if needPtr {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	default:
		return reflect.ValueOf(data)
	}
}
