package main

import (
	"github.com/vhqr0/gostack/stack"
)

func main() {
	iface := stack.NewIface("eth0", "tap0", 1500, "00:00:01:00:00:01", "10.0.0.1/24")
	stack := stack.NewStack([]*stack.Iface{iface})
	stack.AutoRoute4()
	stack.AddRoute4("eth0", "10.0.0.2", "10.0.0.1", "0.0.0.0/0")

	stack.Verbose = true
	stack.Run()
}
