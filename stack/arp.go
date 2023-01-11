package stack

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
)

const (
	ARP_ETH     = 0x0001
	ARP_IPV4    = 0x0800
	ARP_REQUEST = 0x0001
	ARP_REPLY   = 0x0002
)

func (stack *Stack) arpRecv(ifidx int, pkt []byte) {
	// hwtyp   uint16  = 0x0001 eth
	// protyp  uint16  = 0x0800 ipv4
	// hwsize  uint8   = 6
	// prosize uint8   = 4
	// opcode  uint16  = 1 request | 2 reply
	// hwsrc   byte[6]
	// ipsrc   byte[4]
	// hwdst   byte[6]
	// ipdst   byte[4]

	if len(pkt) < 28 {
		if stack.Verbose {
			log.Print("arp: invalid length")
		}
		return
	}

	hwtyp := binary.BigEndian.Uint16(pkt[:2])
	protyp := binary.BigEndian.Uint16(pkt[2:4])
	hwsize := pkt[4]
	prosize := pkt[5]

	if hwtyp != ARP_ETH || protyp != ARP_IPV4 || hwsize != 6 || prosize != 4 {
		if stack.Verbose {
			log.Print("arp: invalid packet")
		}
		return
	}

	opcode := binary.BigEndian.Uint16(pkt[6:8])
	switch opcode {
	case ARP_REQUEST:
		stack.arpRequestRecv(ifidx, pkt)
	case ARP_REPLY:
		stack.arpReplyRecv(ifidx, pkt)
	default:
		if stack.Verbose {
			log.Print("arp: invalid type")
		}
	}
}

func (stack *Stack) arpRequestRecv(ifidx int, pkt []byte) {
	iface := stack.ifaces[ifidx]

	if _, ok := stack.ipFilter[string(pkt[24:28])]; !ok {
		if stack.Verbose {
			log.Printf("arp request: drop %v", net.IP(pkt[24:28]))
		}
		return
	}

	if stack.Verbose {
		log.Printf("arp request: recv %v", net.IP(pkt[14:18]))
	}

	binary.BigEndian.PutUint16(pkt[6:8], ARP_REPLY)

	// save origin ip dst
	ipdst := make([]byte, 4)
	copy(ipdst, pkt[24:28])

	// copy origin src to dst
	copy(pkt[18:24], pkt[8:14])
	copy(pkt[24:28], pkt[14:18])

	// copy origin ip dst to ip src
	copy(pkt[14:18], ipdst)

	// copy mac to mac src
	copy(pkt[8:14], iface.mac)

	stack.ethSend(ifidx, ETH_P_ARP, pkt, pkt[18:24])
}

func (stack *Stack) arpReplyRecv(ifidx int, pkt []byte) {
	iface := stack.ifaces[ifidx]

	if !bytes.Equal(pkt[18:24], iface.mac) {
		if stack.Verbose {
			log.Printf("arp reply: drop %v", net.HardwareAddr(pkt[18:24]))
		}
		return
	}

	if stack.Verbose {
		log.Printf("arp reply: recv %v", net.IP(pkt[14:18]))
	}

	ip := net.IP(pkt[14:18])
	mac := net.HardwareAddr(pkt[8:14])

	stack.neighTable.update(neigh4Key(ifidx, ip), mac)
}

func (stack *Stack) arpRequestSend(ifidx int, ip net.IP) {
	if stack.Verbose {
		log.Printf("arp request: send %v", ip)
	}

	iface := stack.ifaces[ifidx]

	pkt := make([]byte, 28)
	binary.BigEndian.PutUint16(pkt[:2], ARP_ETH)
	binary.BigEndian.PutUint16(pkt[2:4], ARP_IPV4)
	pkt[4] = 6
	pkt[5] = 4
	binary.BigEndian.PutUint16(pkt[6:8], ARP_REQUEST)
	copy(pkt[8:14], iface.mac)
	copy(pkt[14:18], iface.ip4)
	copy(pkt[24:28], []byte(ip))

	stack.ethSend(ifidx, ETH_P_ARP, pkt, []byte(ETH_BROADCAST))
}
