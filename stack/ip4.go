package stack

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/vhqr0/gostack/stack/util"
)

const (
	IPPROTO_ICMP   = 1
	IPPROTO_TCP    = 6
	IPPROTO_UDP    = 17
	IPPROTO_ICMPV6 = 58

	IP_BROADCAST = "\xff\xff\xff\xff"
)

func (stack *Stack) ip4Recv(ifidx int, pkt []byte) {
	// ver|hlen          uint8  = 0x45
	// tos               uint8
	// tlen              uint16
	// id                uint16
	// flags|frag_offset uint16 = 0
	// ttl               uint8
	// proto             uint8
	// cksum             uint16
	// src               byte[4]
	// dst               byte[4]

	if len(pkt) < 20 {
		return
	}

	ver := (pkt[0] & 0xf0) >> 4
	hlen := pkt[0] & 0xf
	tlen := binary.BigEndian.Uint16(pkt[2:4])

	if ver != 4 || hlen != 5 {
		return
	}

	if len(pkt) < int(tlen) {
		return
	}

	pkt = pkt[:tlen]

	dstKey := string(pkt[16:20])

	if dstKey != IP_BROADCAST {
		if _, ok := stack.ipFilter[dstKey]; !ok {
			if stack.Verbose {
				log.Printf("ip4: drop %v", net.IP(pkt[16:20]))
			}
			return
		}
	}

	flags := (pkt[6] & 0xe0) >> 5
	frag_offsets := binary.BigEndian.Uint16(pkt[6:8]) & 0x1fff
	if flags&0x1 != 0 || frag_offsets != 0 {
		if stack.Verbose {
			log.Printf("ip4: drop fragment %v", net.IP(pkt[16:20]))
		}
		return
	}

	proto := pkt[9]
	src := pkt[12:16]
	dst := pkt[16:20]
	pkt = pkt[20:]

	if stack.Verbose {
		log.Printf("ip4: recv %v", net.IP(src))
	}

	switch proto {
	case IPPROTO_ICMP:
		stack.icmp4Recv(pkt, ifidx, src, dst)
	case IPPROTO_TCP:
		// TODO
	case IPPROTO_UDP:
		// TODO
	default:
		if stack.Verbose {
			log.Printf("ip4: invalid protocol")
		}
	}
}

func (stack *Stack) ip4Send(proto uint8, payload []byte, ifidx int, dst, src net.IP) (err error) {
	if stack.Verbose {
		log.Printf("ip4: send %v", dst)
	}

	id := stack.ipID
	stack.ipID++

	tlen := 20 + len(payload)

	pkt := make([]byte, tlen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(tlen))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	pkt[8] = 0xff
	pkt[9] = proto
	if src != nil {
		copy(pkt[12:16], src)
	}
	copy(pkt[16:20], dst)
	copy(pkt[20:], payload)

	dstKey := string(dst)

	if _, ok := stack.ipFilter[dstKey]; ok || dst[0] == 127 {
		if src == nil {
			copy(pkt[12:16], dst)
		}
		stack.ip4Recv(-1, pkt)
		return
	}

	if dstKey == IP_BROADCAST {
		iface := stack.ifaces[ifidx]
		if src == nil {
			copy(pkt[12:16], iface.ip4)
		}
		cksum := util.CheckSum(pkt)
		binary.BigEndian.PutUint16(pkt[10:12], cksum)
		stack.ethSend(ifidx, ETH_P_IPV4, pkt, []byte(ETH_BROADCAST))
		return
	}

	entry := stack.routeTable.next(4, dst)

	if entry == nil {
		err = &DstUnreachError{Dst: dst}
		if stack.Verbose {
			log.Printf("ip4 send: %v", err)
		}
		return
	}

	if src == nil {
		copy(pkt[12:16], entry.src)
	}

	cksum := util.CheckSum(pkt)
	binary.BigEndian.PutUint16(pkt[10:12], cksum)

	if entry.dst != nil {
		dst = entry.dst
	}

	iface := stack.ifaces[entry.idx]
	if len(pkt) > iface.mtu {
		err = &PktTooBigError{}
		if stack.Verbose {
			log.Printf("ip4 send: %v", err)
		}
		return
	}

	mac := stack.neigh4Lookup(entry.idx, dst)
	if mac == nil {
		err = &HostUnreachError{Host: dst}
		if stack.Verbose {
			log.Printf("ip4 send: %v", err)
		}
		return
	}

	stack.ethSend(entry.idx, ETH_P_IPV4, pkt, mac)
	return
}
