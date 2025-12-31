package tlv

import (
	"bytes"
	"encoding/binary"
)

// Int16ToBytes converts an int16 to a byte slice.
func int16_to_bytes(i int16) []byte {
	data := int16(i)
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, data) // Big-endian encoding
	return buffer.Bytes()
}

// Uint16ToBytes converts an uint16 to a byte slice.
func uint16_to_bytes(i uint16) []byte {
	// Convert int to int32 for consistent size
	data := uint16(i)
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, data) // Big-endian encoding
	return buffer.Bytes()
}

// Int64ToBytes converts an int64 to a byte slice.
func int64_to_bytes(n int64) []byte {
	// Convert int to int32 for consistent size
	data := int64(n)
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, data) // Big-endian encoding
	return buffer.Bytes()
}

// uint_to_bytes converts an uint to a byte slice.
func uint_to_bytes(n uint) []byte {
	// Convert int to int32 for consistent size
	data := uint(n)
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, data) // Big-endian encoding
	return buffer.Bytes()
}

// uint64_to_bytes converts an uint32 to a byte slice.
func uint64_to_bytes(n uint64) []byte {
	// Convert int to int32 for consistent size
	data := uint64(n)
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, data) // Big-endian encoding
	return buffer.Bytes()
}

// uint32_to_bytes converts an uint32 to a byte slice.
func uint32_to_bytes(i uint32) []byte {
	// Convert int to int32 for consistent size
	data := uint32(i)
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, data) // Big-endian encoding
	return buffer.Bytes()
}

// int32_to_bytes converts an int32 to a byte slice.
func int32_to_bytes(i int32) []byte {
	// Convert int to int32 for consistent size
	data := int32(i)
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, data) // Big-endian encoding
	return buffer.Bytes()
}
