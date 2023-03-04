package main

import (
	"encoding/binary"
	"errors"
)

const (
	SACP_data_len = 60 * 1024 // just as defined in original python code
)

var (
	errInvalidSACP    = errors.New("data doesn't look like SACP packet")
	errInvalidSACPVer = errors.New("SACP version missmatch")
	errInvalidChksum  = errors.New("SACP checksum doesn't match data")
	errInvalidSize    = errors.New("SACP package is too short")
)

type SACP_pack struct {
	// 0xAA byte
	// 0x55 byte
	// DataLength uint16
	// 0x01 (SACP version)
	ReceiverID byte
	// head_chksum byte
	SenderID   byte
	Attribute  byte
	Sequence   uint16
	CommandSet byte
	CommandID  byte
	Data       []byte
	// data_checksum uint16
}

func (sacp *SACP_pack) Encode() []byte {
	result := make([]byte, 15+len(sacp.Data))

	result[0] = 0xAA
	result[1] = 0x55
	binary.LittleEndian.PutUint16(result[2:3], uint16(len(sacp.Data)))
	result[4] = 0x01
	result[5] = sacp.ReceiverID
	result[6] = sacp.headChksum(result[:6])
	result[7] = sacp.SenderID
	result[8] = sacp.Attribute
	binary.LittleEndian.PutUint16(result[9:10], sacp.Sequence)
	result[11] = sacp.CommandSet
	result[12] = sacp.CommandID

	if len(sacp.Data) > 0 { // this also include check on nil
		copy(result[13:], sacp.Data)
	}

	binary.LittleEndian.PutUint16(result[len(result)-2:], sacp.U16Chksum(result[7:], len(sacp.Data)+6))

	return result[:]
}

func (sacp *SACP_pack) Decode(data []byte) error {
	if len(data) < 13 {
		return errInvalidSize
	}
	if data[0] != 0xAA || data[1] != 0x55 {
		return errInvalidSACP
	}
	dataLen := binary.LittleEndian.Uint16(data[2:3])
	if int(dataLen) != (len(data) - 7) { // why -7 ?!?!?
		return errInvalidSize
	}
	if data[4] != 0x01 {
		return errInvalidSACPVer
	}
	if sacp.headChksum(data[:6]) != data[6] {
		return errInvalidChksum
	}
	if binary.LittleEndian.Uint16(data[len(data)-2:]) != sacp.U16Chksum(data[7:], int(dataLen)-2) {
		return errInvalidChksum
	}

	sacp.ReceiverID = data[5]
	sacp.SenderID = data[7]
	sacp.Attribute = data[8]
	sacp.Sequence = binary.LittleEndian.Uint16(data[9:10])
	sacp.CommandSet = data[11]
	sacp.CommandID = data[12]
	sacp.Data = data[13 : len(data)-2]

	return nil
}

func (sacp *SACP_pack) headChksum(data []byte) byte {
	crc := 0
	poly := 7
	for i := 0; i < len(data); i++ {
		for j := 0; j < 8; j++ {
			bit := data[i]&255>>(7-j)&1 == 1
			c07 := crc>>7&1 == 1
			crc = crc << 1
			if (!c07 && bit) || (c07 && !bit) {
				crc ^= poly
			}
		}
	}
	crc = crc & 255
	return byte(crc)
}

func (sacp *SACP_pack) U16Chksum(package_data []byte, length int) uint16 {
	check_num := uint64(0)
	if length > 0 {
		for i := 0; i < int(length)-1; i += 2 {
			check_num += uint64(package_data[i])<<8 | uint64(package_data[i+1])
			check_num &= 0xffffffff // TODO: maybe just use uint32?
		}
		if length%2 == 0 {
			check_num += uint64(package_data[length-1])
		}
	}
	for check_num > 0xFFFF {
		check_num = ((check_num >> 16) & 0xFFFF) + (check_num & 0xFFFF)
	}
	check_num = ^check_num
	return uint16(check_num & 0xFFFF)
}
