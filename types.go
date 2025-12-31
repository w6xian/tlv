package tlv

import (
	"reflect"
)

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
