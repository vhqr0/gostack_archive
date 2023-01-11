package stack

import (
	"encoding/binary"
	"log"
	"net"
	"sync"

	"github.com/vhqr0/gostack/stack/util"
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

func (stack *Stack) tcpRecv(ver int, pkt []byte, ifidx int, src, dst net.IP) {
	// sport      uint16
	// dport      uint16
	// seqnum     uint32
	// acknum     uint32
	// hlen|flags uint16
	// wsize      uint16
	// cksum      uint16
	// urgptr     uint16

	if len(pkt) < 20 {
		if stack.Verbose {
			log.Print("tcp: invalid length")
		}
		return
	}

	sport := binary.BigEndian.Uint16(pkt[:2])
	dport := binary.BigEndian.Uint16(pkt[2:4])
	// seqnum := binary.BigEndian.Uint32(pkt[4:8])
	// acknum := binary.BigEndian.Uint32(pkt[8:12])
	flags := binary.BigEndian.Uint16(pkt[12:14])
	hlen := (flags & 0xf000) >> 10

	if len(pkt) < int(hlen) {
		if stack.Verbose {
			log.Print("tcp: invalid packet length")
		}
		return
	}

	pkt = pkt[hlen:]

	fin := (flags & TCP_FIN) != 0
	syn := (flags & TCP_SYN) != 0
	rst := (flags & TCP_RST) != 0
	ack := (flags & TCP_ACK) != 0

	if stack.Verbose {
		log.Printf("tcp: recv %v %d, fsra: %v %v %v %v", src, sport, fin, syn, rst, ack)
	}

	if rst {
		key := connKey(ver, dst, dport, src, sport)
		stack.tcpSockTable.mutex.RLock()
		sock, ok := stack.tcpSockTable.entries[key]
		stack.tcpSockTable.mutex.RUnlock()
		if !ok || sock.state == TCP_CLOSED || sock.state == TCP_TIME_WAIT {
			if stack.Verbose {
				log.Print("tcp: drop unmatched rst")
			}
			return
		}
		sock.state = TCP_CLOSED
		close(sock.recvCh)
		close(sock.sendCh)
		sock.recvCh = nil
		sock.sendCh = nil
	} else if !ack {
		if !syn {
			if stack.Verbose {
				log.Print("tcp: drop non-ack and non-syn packet")
			}
			return
		}

		// passive open
		key := listenKey(ver, dst, dport)
		stack.tcpSockTable.mutex.RLock()
		sock, ok := stack.tcpSockTable.entries[key]
		stack.tcpSockTable.mutex.RUnlock()
		if !ok || sock.state != TCP_LISTEN {
			stack.tcpRstSend(ver, sport, dport, ifidx, src, dst)
			if stack.Verbose {
				log.Print("tcp: drop unmatched syn")
			}
			return
		}
		// TODO: do passive open
	} else {
		// TODO: match and act on connection
	}
}

func (stack *Stack) tcpSend(ver int, seq, ack uint32, flags uint16, payload []byte,
	dport, sport uint16, ifidx int, dst, src net.IP) {
	if stack.Verbose {
		log.Printf("tcp: send %v %d", dst, dport)
	}

	tlen := 20 + len(payload)

	pkt := make([]byte, tlen)

	binary.BigEndian.PutUint16(pkt[:2], uint16(sport))
	binary.BigEndian.PutUint16(pkt[2:4], uint16(dport))
	binary.BigEndian.PutUint32(pkt[4:8], seq)
	binary.BigEndian.PutUint32(pkt[8:12], ack)
	binary.BigEndian.PutUint16(pkt[12:14], 0x5000|flags)
	binary.BigEndian.PutUint16(pkt[14:16], 4096) // wsize
	copy(pkt[20:], payload)

	switch ver {
	case 4:
		cksum := util.TCP4CheckSum(pkt, src, dst)
		binary.BigEndian.PutUint16(pkt[16:18], cksum)
		stack.ip4Send(IPPROTO_TCP, pkt, ifidx, dst, src)
	case 6:
		// TODO
	}
}

func (stack *Stack) tcpSockSend(sock *tcpSock, seq, ack uint32, flags uint16, payload []byte) {
	stack.tcpSend(sock.ver, seq, ack, flags, payload,
		uint16(sock.peer.Port), uint16(sock.local.Port),
		sock.ifidx, sock.peer.IP, sock.local.IP)
}

func (stack *Stack) tcpRstSend(ver int, dport, sport uint16, ifidx int, dst, src net.IP) {
	stack.tcpSend(ver, 0, 0, TCP_RST, nil, dport, sport, ifidx, dst, src)
}
