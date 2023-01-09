package stack

import (
	"encoding/binary"
	"net"
)

func neigh4Key(ifidx int, ip net.IP) string {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[:2], uint16(ifidx))
	copy(buf[2:6], ip)
	return string(buf)
}

func conn4Key(localIP net.IP, localPort uint16, peerIP net.IP, peerPort uint16) string {
	buf := make([]byte, 12)
	copy(buf[:4], localIP)
	binary.BigEndian.PutUint16(buf[4:6], localPort)
	copy(buf[6:10], peerIP)
	binary.BigEndian.PutUint16(buf[10:12], peerPort)
	return string(buf)
}

func listen4Key(ip net.IP, port uint16) string {
	buf := make([]byte, 6)
	copy(buf[:4], ip)
	binary.BigEndian.PutUint16(buf[4:6], port)
	return string(buf)
}
