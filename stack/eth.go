package stack

import (
	"encoding/binary"
	"log"
	"net"
)

const (
	ETH_P_ARP  = 0x0806
	ETH_P_IPV4 = 0x0800
	ETH_P_IPV6 = 0x86dd

	ETH_BROADCAST = "\xff\xff\xff\xff\xff\xff"
)

func (stack *Stack) ethReceiver(ifidx int) {
	iface := stack.ifaces[ifidx]
	for {
		pkt := make([]byte, 4096)
		if n, err := iface.tap.Read(pkt); err != nil {
			log.Fatal(err)
		} else {
			pkt = pkt[:n]
		}
		go stack.ethRecv(ifidx, pkt)
	}
}

func (stack *Stack) ethRecv(ifidx int, pkt []byte) {
	// dst byte[6]
	// src byte[6]
	// typ uint16

	iface := stack.ifaces[ifidx]

	if len(pkt) < 14 {
		return
	}

	if _, ok := iface.macFilter[string(pkt[:6])]; !ok {
		return
	}

	if stack.Verbose {
		log.Printf("eth: recv %v", net.HardwareAddr(pkt[6:12]))
	}

	typ := binary.BigEndian.Uint16(pkt[12:14])
	pkt = pkt[14:]
	switch typ {
	case ETH_P_ARP:
		stack.arpRecv(ifidx, pkt)
	case ETH_P_IPV4:
		stack.ip4Recv(ifidx, pkt)
	case ETH_P_IPV6:
		// TODO
	}
}

func (stack *Stack) ethSend(ifidx int, typ uint16, payload []byte, dst net.HardwareAddr) {
	if stack.Verbose {
		log.Printf("eth: send %v", dst)
	}

	iface := stack.ifaces[ifidx]

	payloadLen := len(payload)
	padLen := 0

	if payloadLen < 48 {
		padLen = 48 - payloadLen
	}

	pkt := make([]byte, 14+payloadLen+padLen)

	binary.BigEndian.PutUint16(pkt[12:14], typ)
	copy(pkt[:6], dst)
	copy(pkt[6:12], iface.mac)
	copy(pkt[14:], payload)

	if _, err := iface.tap.Write(pkt); err != nil {
		log.Fatal(err)
	}
}
