package stack

import (
	"log"
	"net"

	"github.com/vhqr0/gostack/util"
)

type Stack struct {
	Verbose bool

	ifaces []*Iface

	neighTable neighTable

	ipID     uint16
	ipFilter map[string]struct{}
	// ip4: string(ip4) len=4
	// ip6: string(ip6) len=16
	routeTable routeTable

	tcpSockTable tcpSockTable
}

func NewStack(ifaces []*Iface) (stack *Stack) {
	stack = &Stack{}
	stack.ifaces = ifaces

	stack.neighTable.entries = make(map[string]*neighEntry)

	stack.ipFilter = make(map[string]struct{})
	for _, iface := range ifaces {
		stack.ipFilter[string(iface.ip4)] = struct{}{}
	}
	stack.routeTable.entries4 = make([]*routeEntry, 0)
	stack.routeTable.entries6 = make([]*routeEntry, 0)

	return
}

func (stack *Stack) AutoRoute4() {
	for ifidx, iface := range stack.ifaces {
		if ones, _ := iface.net4.Mask.Size(); ones == 32 {
			continue
		}
		entry := &routeEntry{
			idx: ifidx,
			dst: nil,
			src: iface.ip4,
			net: iface.net4,
		}
		stack.routeTable.add(4, entry)
	}
}

func (stack *Stack) AddRoute4(ifname, dstStr, srcStr, netStr string) {
	entry := &routeEntry{}

	entry.idx = -1
	for ifidx, iface := range stack.ifaces {
		if iface.name == ifname {
			entry.idx = ifidx
			break
		}
	}
	if entry.idx == -1 {
		log.Fatalf("invalid interface name %s", ifname)
	}

	if dstStr != "" {
		if ip4, err := util.ParseIP4(dstStr); err != nil {
			log.Fatal(err)
		} else {
			entry.dst = ip4
		}
	}

	if ip4, err := util.ParseIP4(srcStr); err != nil {
		log.Fatal(err)
	} else {
		entry.src = ip4
	}

	if _, ipnet, err := net.ParseCIDR(netStr); err != nil {
		log.Fatal(err)
	} else {
		entry.net = ipnet
	}

	stack.routeTable.add(4, entry)
}

func (stack *Stack) Run() {
	for ifidx := range stack.ifaces {
		go stack.ethReceiver(ifidx)
	}
	ch := make(chan struct{})
	<-ch
}
