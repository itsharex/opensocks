package proto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"

	"github.com/net-byte/opensocks/common/cipher"
)

// Encode encodes a byte array into a byte array
func Encode(data []byte) ([]byte, error) {
	length := int32(len(data))
	pkg := new(bytes.Buffer)
	err := binary.Write(pkg, binary.LittleEndian, length)
	if err != nil {
		return nil, err
	}
	err = binary.Write(pkg, binary.LittleEndian, data)
	if err != nil {
		return nil, err
	}
	return pkg.Bytes(), nil
}

// Decode decodes a byte array into a byte array
func Decode(reader *bufio.Reader) (int, []byte, error) {
	len, _ := reader.Peek(4)
	blen := bytes.NewBuffer(len)
	var dlen int32
	err := binary.Read(blen, binary.LittleEndian, &dlen)
	if err != nil {
		return 0, nil, err
	}
	if int32(reader.Buffered()) < dlen+4 {
		return 0, nil, err
	}
	pack := make([]byte, 4+dlen)
	_, err = reader.Read(pack)
	if err != nil {
		return 0, nil, err
	}
	return int(dlen), pack[4:], nil
}

// PaddingEncode encodes a byte array into a byte array
func PaddingEncode(data []byte) ([]byte, error) {
	var dataLen = int32(len(data))
	if dataLen == 0 {
		return nil, errors.New("data is empty")
	}
	var totalLen int32 = 0
	var randomLen int32 = 0
	var randomData []byte
	size := 0
	if dataLen < 1000 {
		min := int(1000 - dataLen)
		max := int(1500 - dataLen)
		size = rand.Intn((max - min + 1) + min)
		randomLen, randomData = cipher.RandomData(size)
	}
	//log.Printf("dataLen:%v randomLen:%v", dataLen, randomLen)
	totalLen = dataLen + randomLen
	pkg := new(bytes.Buffer)
	err := binary.Write(pkg, binary.LittleEndian, totalLen)
	if err != nil {
		return nil, err
	}
	err = binary.Write(pkg, binary.LittleEndian, dataLen)
	if err != nil {
		return nil, err
	}
	err = binary.Write(pkg, binary.LittleEndian, data)
	if err != nil {
		return nil, err
	}
	if randomLen > 0 {
		err = binary.Write(pkg, binary.LittleEndian, randomData)
		if err != nil {
			return nil, err
		}
	}
	return pkg.Bytes(), nil
}

// PaddingDecode decodes a byte array into a byte array
func PaddingDecode(reader *bufio.Reader) (int, []byte, error) {
	// read total length
	size, _ := reader.Peek(4)
	buffer := bytes.NewBuffer(size)
	var totalLen int32
	err := binary.Read(buffer, binary.LittleEndian, &totalLen)
	if err != nil {
		return 0, nil, err
	}
	if totalLen == 0 {
		return 0, nil, errors.New("data is empty")
	}
	if int32(reader.Buffered()) < 8+totalLen {
		return 0, nil, err
	}
	//log.Printf("totalLen:%v", totalLen)
	pack := make([]byte, 8+totalLen)
	_, err = reader.Read(pack)
	if err != nil {
		return 0, nil, err
	}
	// read data length
	dataLen := int32(binary.LittleEndian.Uint32(pack[4:8]))
	data := pack[8 : 8+dataLen]
	return int(dataLen), data, nil
}
