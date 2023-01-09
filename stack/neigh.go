package stack

import (
	"net"
	"sync"
	"time"
)

type neighTable struct {
	mutex   sync.RWMutex
	entries map[string]*neighEntry
	// ip4 => neigh4Key(ifidx, ip4) len=6
	// ip6 => neigh6Key(ifidx, ip6) len=18
}

type neighEntry struct {
	ts  int64
	mac net.HardwareAddr
}

func (table *neighTable) lookup(key string) (mac net.HardwareAddr) {
	table.mutex.RLock()
	entry, ok := table.entries[key]
	if ok && entry != nil && entry.ts+60 > time.Now().Unix() {
		mac = entry.mac
	}
	table.mutex.RUnlock()
	return
}

func (table *neighTable) update(key string, mac net.HardwareAddr) {
	table.mutex.Lock()
	entry, ok := table.entries[key]
	if !ok {
		entry = &neighEntry{}
		table.entries[key] = entry
	}
	entry.ts = time.Now().Unix()
	entry.mac = mac
	table.mutex.Unlock()
}

func (stack *Stack) neigh4Lookup(ifidx int, ip net.IP) (mac net.HardwareAddr) {
	key := neigh4Key(ifidx, ip)

	mac = stack.neighTable.lookup(key)
	if mac != nil {
		return
	}

	stack.arpRequestSend(ifidx, ip)
	time.Sleep(10 * time.Millisecond)
	mac = stack.neighTable.lookup(key)
	return
}
