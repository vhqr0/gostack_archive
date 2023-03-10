package util

import (
	"encoding/binary"
	"net"
)

func CheckSum(msg []byte) uint16 {
	sum := uint32(0)
	var i int
	for i = 0; i < len(msg)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(msg[i : i+2]))
	}
	if i == len(msg)-1 { // odd
		sum += uint32(uint16(msg[i]) << 8)
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	return ^uint16(sum)
}

func TCP4CheckSum(msg []byte, src, dst net.IP) uint16 {
	buf := make([]byte, len(msg)+8)
	copy(buf[:4], src)
	copy(buf[4:8], dst)
	copy(buf[8:], msg)
	return CheckSum(buf)
}
