package stack

import (
	"log"
	"net"
	"os"

	"github.com/vhqr0/gostack/util"
)

type Iface struct {
	name string

	tap  *os.File
	mtu  int
	mac  net.HardwareAddr
	ip4  net.IP
	net4 *net.IPNet

	macFilter map[string]struct{}
	// string(mac)
}

func NewIface(name, tapIfaceName string, mtu int, macStr, cidr4Str string) (iface *Iface) {
	iface = &Iface{}
	iface.name = name
	if tap, err := util.OpenTap(tapIfaceName); err != nil {
		log.Fatal(err)
	} else {
		iface.tap = tap
	}
	iface.mtu = mtu
	if mac, err := net.ParseMAC(macStr); err != nil {
		log.Fatal(err)
	} else {
		iface.mac = mac
	}
	if ip4, net4, err := util.ParseCIDR4(cidr4Str); err != nil {
		log.Fatal(err)
	} else {
		iface.ip4 = ip4
		iface.net4 = net4
	}
	iface.macFilter = make(map[string]struct{})
	iface.macFilter[ETH_BROADCAST] = struct{}{}
	iface.macFilter[string(iface.mac)] = struct{}{}
	return
}
