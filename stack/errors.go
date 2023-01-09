package stack

import (
	"fmt"
	"net"
)

type DstUnreachError struct {
	Dst net.IP
}

func (err *DstUnreachError) Error() string {
	return fmt.Sprintf("destination unreachable: %v", err.Dst)
}

type HostUnreachError struct {
	Host net.IP
}

func (err *HostUnreachError) Error() string {
	return fmt.Sprintf("host unreachable: %v", err.Host)
}

type PktTooBigError struct{}

func (err *PktTooBigError) Error() string {
	return "packet too big"
}
