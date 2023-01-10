package stack

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/vhqr0/gostack/stack/util"
)

const (
	ICMP_ECHOREPLY = 0
	ICMP_ECHO      = 8
)

func (stack *Stack) icmp4Recv(pkt []byte, ifidx int, src, dst net.IP) {
	// typ   uint8
	// code  uint8
	// cksum uint16

	if len(pkt) < 16 {
		return
	}

	typ := pkt[0]
	switch typ {
	case ICMP_ECHO:
		stack.icmp4EchoRecv(pkt, ifidx, src, dst)
	// default:
	// 	if stack.Verbose {
	// 		log.Printf("icmp4: invalid type")
	// 	}
	}
}

func (stack *Stack) icmp4EchoRecv(pkt []byte, ifidx int, src, dst net.IP) {
	if stack.Verbose {
		log.Printf("icmp4 echo: recv %v", net.IP(src))
	}

	pkt[0] = ICMP_ECHOREPLY
	binary.BigEndian.PutUint16(pkt[2:4], 0)
	cksum := util.CheckSum(pkt)
	binary.BigEndian.PutUint16(pkt[2:4], cksum)
	stack.ip4Send(IPPROTO_ICMP, pkt, ifidx, src, dst)
}
