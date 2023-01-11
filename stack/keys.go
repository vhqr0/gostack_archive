package stack

import (
	"encoding/binary"
	"net"
)

func neighKey(ver, ifidx int, ip net.IP) string {
	switch ver {
	case 4:
		return neigh4Key(ifidx, ip)
	case 6:
		return neigh6Key(ifidx, ip)
	}
	return ""
}

func neigh4Key(ifidx int, ip net.IP) string {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[:2], uint16(ifidx))
	copy(buf[2:6], ip)
	return string(buf)
}

func neigh6Key(ifidx int, ip net.IP) string {
	buf := make([]byte, 18)
	binary.BigEndian.PutUint16(buf[:2], uint16(ifidx))
	copy(buf[2:18], ip)
	return string(buf)
}

func connKey(ver int, localIP net.IP, localPort uint16, peerIP net.IP, peerPort uint16) string {
	switch ver {
	case 4:
		return conn4Key(localIP, localPort, peerIP, peerPort)
	case 6:
		return conn6Key(localIP, localPort, peerIP, peerPort)
	}
	return ""
}

func conn4Key(localIP net.IP, localPort uint16, peerIP net.IP, peerPort uint16) string {
	buf := make([]byte, 12)
	copy(buf[:4], localIP)
	binary.BigEndian.PutUint16(buf[4:6], localPort)
	copy(buf[6:10], peerIP)
	binary.BigEndian.PutUint16(buf[10:12], peerPort)
	return string(buf)
}

func conn6Key(localIP net.IP, localPort uint16, peerIP net.IP, peerPort uint16) string {
	buf := make([]byte, 36)
	copy(buf[:16], localIP)
	binary.BigEndian.PutUint16(buf[16:18], localPort)
	copy(buf[18:34], peerIP)
	binary.BigEndian.PutUint16(buf[34:36], peerPort)
	return string(buf)
}

func listenKey(ver int, ip net.IP, port uint16) string {
	switch ver {
	case 4:
		return listen4Key(ip, port)
	case 6:
		return listen6Key(ip, port)
	}
	return ""
}

func listen4Key(ip net.IP, port uint16) string {
	buf := make([]byte, 6)
	copy(buf[:4], ip)
	binary.BigEndian.PutUint16(buf[4:6], port)
	return string(buf)
}

func listen6Key(ip net.IP, port uint16) string {
	buf := make([]byte, 18)
	copy(buf[:16], ip)
	binary.BigEndian.PutUint16(buf[16:18], port)
	return string(buf)
}
