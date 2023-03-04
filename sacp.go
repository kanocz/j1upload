package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"time"
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

func (sacp SACP_pack) Encode() []byte {
	result := make([]byte, 15+len(sacp.Data))

	result[0] = 0xAA
	result[1] = 0x55
	binary.LittleEndian.PutUint16(result[2:4], uint16(len(sacp.Data)+6+2))
	result[4] = 0x01
	result[5] = sacp.ReceiverID
	result[6] = sacp.headChksum(result[:6])
	result[7] = sacp.SenderID
	result[8] = sacp.Attribute
	binary.LittleEndian.PutUint16(result[9:11], sacp.Sequence)
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
	dataLen := binary.LittleEndian.Uint16(data[2:4])
	if int(dataLen) != (len(data) - 7) {
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
	sacp.Sequence = binary.LittleEndian.Uint16(data[9:11])
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
		for i := 0; i < length-1; i += 2 {
			check_num += uint64(package_data[i])<<8 | uint64(package_data[i+1])
			check_num &= 0xffffffff // TODO: maybe just use uint32?
		}
		if length%2 != 0 {
			check_num += uint64(package_data[length-1])
		}
	}
	for check_num > 0xFFFF {
		check_num = ((check_num >> 16) & 0xFFFF) + (check_num & 0xFFFF)
	}
	check_num = ^check_num
	return uint16(check_num & 0xFFFF)
}

func writeSACPstring(w io.Writer, s string) {
	binary.Write(w, binary.LittleEndian, uint16(len(s)))
	w.Write([]byte(s))
}

func writeLE[T any](w io.Writer, u T) {
	binary.Write(w, binary.LittleEndian, u)
}

func SACP_connect(ip string, timeout time.Duration) net.Conn {
	conn, err := net.Dial("tcp4", ip+":8888")
	if err != nil {
		log.Printf("Error connecting to %s: %v", ip, err)
		return nil
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write(SACP_pack{
		ReceiverID: 2,
		SenderID:   0,
		Attribute:  0,
		Sequence:   1,
		CommandSet: 0x01,
		CommandID:  0x05,
		Data: []byte{
			6, 0, 'D', 'e', 's', 't', 'o', 'p',
			8, 0, 'j', '1', 'u', 'p', 'l', 'o', 'a', 'd',
			0, 0,
		},
	}.Encode())

	if err != nil {
		log.Println("Error writing \"hello\": ", err)
		conn.Close()
		return nil
	}

	p, err := SACP_read(conn, timeout)
	if err != nil {
		log.Println("Error reading \"hello\" responce: ", err)
		conn.Close()
		return nil
	}

	log.Printf("Got reply from printer on hello: %v", p)

	return conn
}

func SACP_read(conn net.Conn, timeout time.Duration) (*SACP_pack, error) {

	var buf [SACP_data_len + 15]byte

	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)

	n, err := conn.Read(buf[:4])
	if err != nil || n != 4 {
		return nil, err
	}

	dataLen := binary.LittleEndian.Uint16(buf[2:4])
	n, err = conn.Read(buf[4 : dataLen+7])
	if err != nil || n != int(dataLen+3) {
		return nil, err
	}

	var sacp SACP_pack
	err = sacp.Decode(buf[:dataLen+7])

	return &sacp, err
}

func SACP_start_upload(conn net.Conn, filename string, gcode []byte) error {
	package_count := (len(gcode) / SACP_data_len) + 1
	md5hash := md5.Sum(gcode)

	data := bytes.Buffer{}

	writeSACPstring(&data, filename)
	writeLE(&data, uint32(len(gcode)))
	writeLE(&data, uint16(package_count))
	writeSACPstring(&data, hex.EncodeToString(md5hash[:]))

	_, err := conn.Write(SACP_pack{
		ReceiverID: 2,
		SenderID:   0,
		Attribute:  0,
		Sequence:   1,
		CommandSet: 0xb0,
		CommandID:  0x00,
		Data:       data.Bytes(),
	}.Encode())

	return err
}
