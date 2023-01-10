package stack

import (
	"net"
)

type routeTable struct {
	entries4 []*routeEntry
	entries6 []*routeEntry
}

type routeEntry struct {
	idx int    // iface index
	dst net.IP // ip of dst mac to lookup, may be nil
	src net.IP // default src ip, cannot be nil
	net *net.IPNet
}

func (table *routeTable) next(ver int, ip net.IP) *routeEntry {
	var entries []*routeEntry
	switch ver {
	case 4:
		entries = table.entries4
	case 6:
		entries = table.entries6
	default:
		return nil
	}
	for _, entry := range entries {
		if entry.net.Contains(ip) {
			return entry
		}
	}
	return nil
}

func (table *routeTable) add(ver int, entry *routeEntry) {
	switch ver {
	case 4:
		table.entries4 = append(table.entries4, entry)
	case 6:
		table.entries6 = append(table.entries6, entry)
	}
}
