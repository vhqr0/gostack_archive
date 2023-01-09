package stack

import (
	"net"
	"sync"
)

const (
	TCP_FIN = 0x01
	TCP_SYN = 0x02
	TCP_RST = 0x04
	TCP_PSH = 0x08
	TCP_ACK = 0x10
	TCP_URG = 0x20
	TCP_ECN = 0x40
	TCP_WIN = 0x80

	TCP_OPT_NOOP = 1
	TCP_OPT_MSS  = 2
	TCP_OPT_SACK = 5
	TCP_OPT_TS   = 8

	TCP_OPTLEN_MSS  = 4
	TCP_OPTLEN_SACK = 2
)

type tcpSockTable struct {
	mutex   sync.RWMutex
	entries map[string]*tcpSock
	// listen4 listen4Key(sip, sport)           len=6
	// conn4   conn4Key(sip, sport, dip, dport) len=12
	// listen6 listen6Key(sip, sport)           len=18
	// conn6   conn6Key(sip, sport, dip, dport) len=36
}

func (stack *Stack) tcpRecv(pkt []byte, ifidx int, src, dst net.IP) {
	// sport      uint16
	// dport      uint16
	// seqnum     uint32
	// acknum     uint32
	// hlen|flags uint16
	// wsize      uint16
	// cksum      uint16
	// urgptr     uint16
}
