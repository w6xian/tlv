package tlv

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
)

func tlv_frame_from_string(v string, opts *Option) int {
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_STRING, []byte(v), opts)
	if err != nil {
		return 0
	}
	return r
}

func tlv_frame_from_json(v any, opts *Option) int {
	jsonData, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	fmt.Println("tlv type json", jsonData)
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_JSON, jsonData, opts)
	if err != nil {
		return 0
	}
	return r
}

func tlv_frame_from_slice(v any, opts *Option) int {
	tag, total := int_data_size(v, opts)
	if total == 0 {
		return 0
	}
	// fmt.Println(tag, total)
	if tag > 0 && total > 0 {
		tag, size := get_tlv_tag(tag, total, opts)
		// fmt.Println(tag, size)
		opts.WriteByte(tag)
		// return r
		dv := get_tlv_len(total, opts)
		opts.Write(dv)
		r, err := write_any_data(opts, v)
		if err != nil {
			return 0
		}
		return r + int(size) + 1
	}

	jsonData, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_SLICE, jsonData, opts)
	if err != nil {
		return 0
	}
	return r
}

// Float32 从float32编码为tlv
func tlv_frame_from_float32(v float32, opts *Option) int {
	bits := math.Float32bits(v)
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(bits >> 24))
	buf.WriteByte(byte(bits >> 16))
	buf.WriteByte(byte(bits >> 8))
	buf.WriteByte(byte(bits))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_FLOAT32, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Float64 从float64编码为tlv
func tlv_frame_from_float64(v float64, opts *Option) int {
	vf := math.Float64bits(v)
	// buf := opts.pool.Get()
	// defer opts.pool.Put(buf)
	// binary.BigEndian.PutUint64(buf[:8], bits)
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(vf >> 56))
	buf.WriteByte(byte(vf >> 48))
	buf.WriteByte(byte(vf >> 40))
	buf.WriteByte(byte(vf >> 32))
	buf.WriteByte(byte(vf >> 24))
	buf.WriteByte(byte(vf >> 16))
	buf.WriteByte(byte(vf >> 8))
	buf.WriteByte(byte(vf))

	r, err := tlv_encode_option_with_buffer(TLV_TYPE_FLOAT64, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Int32 从int32编码为tlv
func tlv_frame_from_int32(v int32, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	// binary.BigEndian.PutUint32(buf[:4], uint32(v))
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_INT32, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Int8 从int8编码为tlv
func tlv_frame_from_int8(v int8, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_INT8, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Int16 从int16编码为tlv
func tlv_frame_from_int16(v int16, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_INT16, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Int 从int编码为tlv
func tlv_frame_from_int(v int, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(v >> 56))
	buf.WriteByte(byte(v >> 48))
	buf.WriteByte(byte(v >> 40))
	buf.WriteByte(byte(v >> 32))
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_INT, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Int64 从int64编码为tlv
func tlv_frame_from_int64(v int64, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(v >> 56))
	buf.WriteByte(byte(v >> 48))
	buf.WriteByte(byte(v >> 40))
	buf.WriteByte(byte(v >> 32))
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_INT64, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Bool 从bool编码为tlv
func tlv_frame_from_bool(v bool, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(0)
	if v {
		buf.WriteByte(1)
	}
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_BOOL, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Complex64 从complex64编码为tlv
func tlv_frame_from_complex64(v complex64, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	r := math.Float32bits(float32(real(complex128(v))))
	i := math.Float32bits(float32(imag(complex128(v))))
	buf.WriteByte(byte(r >> 24))
	buf.WriteByte(byte(r >> 16))
	buf.WriteByte(byte(r >> 8))
	buf.WriteByte(byte(r))
	buf.WriteByte(byte(i >> 24))
	buf.WriteByte(byte(i >> 16))
	buf.WriteByte(byte(i >> 8))
	buf.WriteByte(byte(i))
	rst, err := tlv_encode_option_with_buffer(TLV_TYPE_COMPLEX64, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return rst
}

// Complex128 从complex128编码为tlv
func tlv_frame_from_complex128(v complex128, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	r := math.Float64bits(real(v))
	i := math.Float64bits(imag(v))
	buf.WriteByte(byte(r >> 56))
	buf.WriteByte(byte(r >> 48))
	buf.WriteByte(byte(r >> 40))
	buf.WriteByte(byte(r >> 32))
	buf.WriteByte(byte(r >> 24))
	buf.WriteByte(byte(r >> 16))
	buf.WriteByte(byte(r >> 8))
	buf.WriteByte(byte(r))
	buf.WriteByte(byte(i >> 56))
	buf.WriteByte(byte(i >> 48))
	buf.WriteByte(byte(i >> 40))
	buf.WriteByte(byte(i >> 32))
	buf.WriteByte(byte(i >> 24))
	buf.WriteByte(byte(i >> 16))
	buf.WriteByte(byte(i >> 8))
	buf.WriteByte(byte(i))
	rst, err := tlv_encode_option_with_buffer(TLV_TYPE_COMPLEX128, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return rst
}

// Nil 从nil编码为tlv
func tlv_frame_from_nil(opts *Option) int {
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_NIL, []byte{0}, opts)
	if err != nil {
		return 0
	}
	return r
}

// Uintptr 从uintptr编码为tlv
func tlv_frame_from_uintptr(v uintptr, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(v >> 56))
	buf.WriteByte(byte(v >> 48))
	buf.WriteByte(byte(v >> 40))
	buf.WriteByte(byte(v >> 32))
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_UINTPTR, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Uint64 从uint64编码为tlv
func tlv_frame_from_uint64(v uint64, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(v >> 56))
	buf.WriteByte(byte(v >> 48))
	buf.WriteByte(byte(v >> 40))
	buf.WriteByte(byte(v >> 32))
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_UINT64, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Uint 从uint编码为tlv
func tlv_frame_from_uint(v uint, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(v >> 56))
	buf.WriteByte(byte(v >> 48))
	buf.WriteByte(byte(v >> 40))
	buf.WriteByte(byte(v >> 32))
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_UINT, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Uint32 从uint32编码为tlv
func tlv_frame_from_uint32(v uint32, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_UINT32, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

// Uint8 从uint8编码为tlv
func tlv_frame_from_uint8(v uint8, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(v)
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_UINT8, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

func tlv_frame_from_uint16(v uint16, opts *Option) int {
	buf := opts.GetEncoder()
	defer opts.PutEncoder(buf)
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
	r, err := tlv_encode_option_with_buffer(TLV_TYPE_UINT16, buf.Bytes(), opts)
	if err != nil {
		return 0
	}
	return r
}

func tlv_bytes_to_float64(v []byte) float64 {
	bits := binary.BigEndian.Uint64(v)
	return math.Float64frombits(bits)
}

// Float64 从float64编码为tlv
func tlv_frame_to_float64(v TLVFrame, opts *Option) (float64, error) {
	t, data, err := tlv_decode_opt(v, opts)
	if err != nil {
		return 0, err
	}
	if len(data) != 8 {
		return 0, ErrInvalidFloat64
	}
	if t != TLV_TYPE_FLOAT64 {
		return 0, ErrInvalidFloat64Type
	}
	fv := tlv_bytes_to_float64(data)
	return fv, nil
}

func tlv_bytes_to_int64(v []byte) int64 {
	return int64(binary.BigEndian.Uint64(v))
}

func tlv_frame_to_int64(v TLVFrame, opts *Option) (int64, error) {
	t, data, err := tlv_decode_opt(v, opts)
	if err != nil {
		return 0, err
	}
	if len(data) != 8 {
		return 0, ErrInvalidInt64
	}
	if t != TLV_TYPE_INT64 {
		return 0, ErrInvalidInt64Type
	}
	return tlv_bytes_to_int64(data), nil
}

func tlv_bytes_to_uint64(v []byte) uint64 {
	return binary.BigEndian.Uint64(v)
}

func tlv_frame_to_uint64(v TLVFrame, opts *Option) (uint64, error) {
	t, data, err := tlv_decode_opt(v, opts)
	if err != nil {
		return 0, err
	}
	if len(data) != 8 {
		return 0, ErrInvalidUint64
	}
	if t != TLV_TYPE_UINT64 {
		return 0, ErrInvalidUint64Type
	}
	return tlv_bytes_to_uint64(data), nil
}

func tlv_deserialize(v []byte, opts *Option) (*TlV, error) {
	if v == nil {
		return nil, ErrInvalidValueLength
	}
	if len(v) < TLVX_HEADER_MIN_SIZE {
		return nil, ErrInvalidValueLength
	}
	tlv, err := tlv_new_from_frame(v, opts)
	if tlv == nil {
		return nil, err
	}
	return tlv, nil
}

func tlv_serialize_value(f reflect.Value, opt *Option) int {
	v := f.Interface()
	if v == nil {
		return 0
	}
	switch k := f.Kind(); k {
	case reflect.Float64:
		return tlv_frame_from_float64(v.(float64), opt)
	case reflect.Float32:
		return tlv_frame_from_float32(v.(float32), opt)
	case reflect.Int:
		return tlv_frame_from_int(v.(int), opt)
	case reflect.Uint:
		return tlv_frame_from_uint(v.(uint), opt)
	case reflect.Int8:
		return tlv_frame_from_int8(v.(int8), opt)
	case reflect.Int16:
		return tlv_frame_from_int16(v.(int16), opt)
	case reflect.Int32:
		return tlv_frame_from_int32(v.(int32), opt)
	case reflect.Int64:
		return tlv_frame_from_int64(v.(int64), opt)
	case reflect.Uint8:
		return tlv_frame_from_uint8(v.(uint8), opt)
	case reflect.Uint16:
		return tlv_frame_from_uint16(v.(uint16), opt)
	case reflect.Uint32:
		return tlv_frame_from_uint32(v.(uint32), opt)
	case reflect.Uint64:
		return tlv_frame_from_uint64(v.(uint64), opt)
	case reflect.Slice:
		return tlv_frame_from_slice(v, opt)
	case reflect.String:
		return tlv_frame_from_string(v.(string), opt)
	case reflect.Bool:
		return tlv_frame_from_bool(v.(bool), opt)
	case reflect.Complex64:
		return tlv_frame_from_complex64(v.(complex64), opt)
	case reflect.Complex128:
		return tlv_frame_from_complex128(v.(complex128), opt)
	case reflect.Uintptr:
		return tlv_frame_from_uintptr(v.(uintptr), opt)
	default:
		fmt.Println("tlv type not found", f.Kind())
		return tlv_frame_from_json(v, opt)
	}
}

func write_any_data(opt *Option, data any) (int, error) {
	switch data := data.(type) {
	case bool, int8, uint8, *bool, *int8, *uint8:
		opt.WriteByte(data.(byte))
		return 1, nil
	case []bool:
		for _, b := range data {
			if b {
				opt.WriteByte(1)
			} else {
				opt.WriteByte(0)
			}
		}
		return len(data), nil
	case []int8:
		for _, b := range data {
			opt.WriteByte(byte(b))
		}
		return len(data), nil
	case []uint8:
		for _, b := range data {
			opt.WriteByte(b)
		}
		return len(data), nil
	case int16, uint16, *int16, *uint16:
		binary.Write(opt, binary.BigEndian, data)
		return 2, nil
	case []int16:
		for _, b := range data {
			binary.Write(opt, binary.BigEndian, b)
		}
		return 2 * len(data), nil
	case []uint16:
		for _, b := range data {
			opt.WriteByte(byte(b >> 8))
			opt.WriteByte(byte(b))
		}
		return 2 * len(data), nil
	case int32, uint32, *int32, *uint32:
		b := data.(uint32)
		opt.WriteByte(byte(b >> 24))
		opt.WriteByte(byte(b >> 16))
		opt.WriteByte(byte(b >> 8))
		opt.WriteByte(byte(b))
		return 4, nil
	case []int32:
		for _, b := range data {
			opt.WriteByte(byte(b >> 24))
			opt.WriteByte(byte(b >> 16))
			opt.WriteByte(byte(b >> 8))
			opt.WriteByte(byte(b))
		}
		return 4 * len(data), nil
	case []uint32:
		for _, b := range data {
			opt.WriteByte(byte(b >> 24))
			opt.WriteByte(byte(b >> 16))
			opt.WriteByte(byte(b >> 8))
			opt.WriteByte(byte(b))
		}
		return 4 * len(data), nil
	case int64, uint64, *int64, *uint64:
		b := data.(uint64)
		opt.WriteByte(byte(b >> 56))
		opt.WriteByte(byte(b >> 48))
		opt.WriteByte(byte(b >> 40))
		opt.WriteByte(byte(b >> 32))
		opt.WriteByte(byte(b >> 24))
		opt.WriteByte(byte(b >> 16))
		opt.WriteByte(byte(b >> 8))
		opt.WriteByte(byte(b))
		return 8, nil
	case []int64:
		for _, b := range data {
			opt.WriteByte(byte(b >> 56))
			opt.WriteByte(byte(b >> 48))
			opt.WriteByte(byte(b >> 40))
			opt.WriteByte(byte(b >> 32))
			opt.WriteByte(byte(b >> 24))
			opt.WriteByte(byte(b >> 16))
			opt.WriteByte(byte(b >> 8))
			opt.WriteByte(byte(b))
		}
		return 8 * len(data), nil
	case []int:
		for _, b := range data {
			opt.WriteByte(byte(b >> 56))
			opt.WriteByte(byte(b >> 48))
			opt.WriteByte(byte(b >> 40))
			opt.WriteByte(byte(b >> 32))
			opt.WriteByte(byte(b >> 24))
			opt.WriteByte(byte(b >> 16))
			opt.WriteByte(byte(b >> 8))
			opt.WriteByte(byte(b))
		}
		return 8 * len(data), nil
	case []uint64:
		for _, b := range data {
			opt.WriteByte(byte(b >> 56))
			opt.WriteByte(byte(b >> 48))
			opt.WriteByte(byte(b >> 40))
			opt.WriteByte(byte(b >> 32))
			opt.WriteByte(byte(b >> 24))
			opt.WriteByte(byte(b >> 16))
			opt.WriteByte(byte(b >> 8))
			opt.WriteByte(byte(b))
		}
		return 8 * len(data), nil
	case []uint:
		for _, b := range data {
			opt.WriteByte(byte(b >> 56))
			opt.WriteByte(byte(b >> 48))
			opt.WriteByte(byte(b >> 40))
			opt.WriteByte(byte(b >> 32))
			opt.WriteByte(byte(b >> 24))
			opt.WriteByte(byte(b >> 16))
			opt.WriteByte(byte(b >> 8))
			opt.WriteByte(byte(b))
		}
		return 8 * len(data), nil
	case float32, *float32:
		b := data.(float32)
		bits := math.Float32bits(b)
		opt.WriteByte(byte(bits >> 24))
		opt.WriteByte(byte(bits >> 16))
		opt.WriteByte(byte(bits >> 8))
		opt.WriteByte(byte(bits))
		return 4, nil
	case float64, *float64:
		b := data.(float64)
		bits := math.Float64bits(b)
		opt.WriteByte(byte(bits >> 56))
		opt.WriteByte(byte(bits >> 48))
		opt.WriteByte(byte(bits >> 40))
		opt.WriteByte(byte(bits >> 32))
		opt.WriteByte(byte(bits >> 24))
		opt.WriteByte(byte(bits >> 16))
		opt.WriteByte(byte(bits >> 8))
		opt.WriteByte(byte(bits))
		return 8, nil
	case []float32:
		for _, b := range data {
			bits := math.Float32bits(b)
			opt.WriteByte(byte(bits >> 24))
			opt.WriteByte(byte(bits >> 16))
			opt.WriteByte(byte(bits >> 8))
			opt.WriteByte(byte(bits))
		}
		return 4 * len(data), nil
	case []float64:
		for _, b := range data {
			bits := math.Float64bits(b)
			opt.WriteByte(byte(bits >> 56))
			opt.WriteByte(byte(bits >> 48))
			opt.WriteByte(byte(bits >> 40))
			opt.WriteByte(byte(bits >> 32))
			opt.WriteByte(byte(bits >> 24))
			opt.WriteByte(byte(bits >> 16))
			opt.WriteByte(byte(bits >> 8))
			opt.WriteByte(byte(bits))
		}
		return 8 * len(data), nil
	case []string:
		l := 0
		for _, s := range data {
			p, err := tlv_encode_option_with_buffer(TLV_TYPE_STRING, []byte(s), opt)
			if err != nil {
				return 0, err
			}
			l += p
		}
		return l, nil
	}
	return 0, errors.New("invalid data type")
}

func set_filed_value(prt bool, tag byte, data []byte, opt *Option) reflect.Value {
	// []string{"int", "int32", "int64", "uint", "uint32", "uint64", "float32", "float64", "string", "uint8", "bool"}
	// fmt.Println(tag, len(data), data)
	switch tag {
	case TLV_TYPE_INT:
		by := bytes_to_int(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_INT8:
		by := bytes_to_int8(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_INT16:
		by := bytes_to_int16(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_INT32:
		by := bytes_to_int32(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_INT64:
		by := bytes_to_int64(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_UINT:
		by := bytes_to_uint(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_UINT8:
		by := bytes_to_uint8(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_UINT16:
		by := bytes_to_uint16(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_UINT32:
		by := bytes_to_uint32(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_UINT64:
		by := bytes_to_uint64(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_FLOAT32:
		by := bytes_to_float32(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_FLOAT64:
		by := bytes_to_float64(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_STRING:
		str := string(data)
		if prt {
			return reflect.ValueOf(&str)
		}
		return reflect.ValueOf(str)
	case TLV_TYPE_BOOL:
		by := bytes_to_bool(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
		// 复数类型
	case TLV_TYPE_COMPLEX64:
		by := bytes_to_complex64(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_COMPLEX128:
		by := bytes_to_complex128(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_UINTPTR:
		by := bytes_to_uintptr(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_RUNE:
		by := bytes_to_rune(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE:
		if prt {
			return reflect.ValueOf(&data)
		}
		return reflect.ValueOf(data)
	case TLV_TYPE_SLICE_BYTE:
		if prt {
			return reflect.ValueOf(&data)
		}
		return reflect.ValueOf(data)
	case TLV_TYPE_SLICE_INT:
		by := conv_to_slice_int(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_INT64:
		by := conv_to_slice_int64(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_UINT:
		by := conv_to_slice_uint(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_UINT64:
		by := conv_to_slice_uint64(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_INT32:
		by := conv_to_slice_int32(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_UINT32:
		by := conv_to_slice_uint32(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_INT16:
		by := conv_to_slice_int16(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_UINT16:
		by := conv_to_slice_uint16(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_STRING:
		by := slice_bytes_to_slice_strings(data, opt)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_FLOAT32:
		by := conv_to_slice_float32(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	case TLV_TYPE_SLICE_FLOAT64:
		by := conv_to_slice_float64(data)
		if prt {
			return reflect.ValueOf(&by)
		}
		return reflect.ValueOf(by)
	default:
		if prt {
			return reflect.ValueOf(&data)
		}
		return reflect.ValueOf(data)
	}
}

func int_data_size(data any, opt *Option) (byte, int) {
	//fmt.Println(data, reflect.TypeOf(data))
	switch data := data.(type) {
	case bool, *bool:
		return TLV_TYPE_BOOL, 1
	case int8, *int8:
		return TLV_TYPE_INT8, 1
	case uint8, *uint8:
		return TLV_TYPE_UINT8, 1
	case int16, *int16:
		return TLV_TYPE_INT16, 2
	case uint16, *uint16:
		return TLV_TYPE_UINT16, 2
	case []bool:
		return TLV_TYPE_SLICE_BOOL, len(data)
	case []int8:
		return TLV_TYPE_SLICE_INT8, len(data)
	case []uint8:
		return TLV_TYPE_SLICE_UINT8, len(data)
	case []int16:
		return TLV_TYPE_SLICE_INT16, 2 * len(data)
	case []uint16:
		return TLV_TYPE_SLICE_UINT16, 2 * len(data)
	case int32, uint32, *int32, *uint32:
		return TLV_TYPE_INT32, 4
	case []int32:
		return TLV_TYPE_SLICE_INT32, 4 * len(data)
	case []int:
		return TLV_TYPE_SLICE_INT, 8 * len(data)
	case []uint:
		return TLV_TYPE_SLICE_UINT, 8 * len(data)
	case []uint32:
		return TLV_TYPE_SLICE_UINT32, 4 * len(data)
	case int64, uint64, *int64, *uint64:
		return TLV_TYPE_INT64, 8
	case []int64:
		return TLV_TYPE_SLICE_INT64, 8 * len(data)
	case []uint64:
		return TLV_TYPE_SLICE_UINT64, 8 * len(data)
	case float32, *float32:
		return TLV_TYPE_FLOAT32, 4
	case float64, *float64:
		return TLV_TYPE_FLOAT64, 8
	case []float32:
		return TLV_TYPE_SLICE_FLOAT32, 4 * len(data)
	case []float64:
		return TLV_TYPE_SLICE_FLOAT64, 8 * len(data)
	case complex64, *complex64:
		return TLV_TYPE_COMPLEX64, 8
	case complex128, *complex128:
		return TLV_TYPE_COMPLEX128, 16
	case []complex64:
		return TLV_TYPE_SLICE_COMPLEX64, 8 * len(data)
	case []complex128:
		return TLV_TYPE_SLICE_COMPLEX128, 16 * len(data)
	case []string:
		total := 0
		for _, s := range data {
			l := len([]byte(s))
			total += l
			total += int(get_tlv_len_size(l, opt))
			total += 1
		}
		return TLV_TYPE_SLICE_STRING, total
	default:
		return 0, 0
	}
}
