package stack

import (
	"net"
)

const (
	_ = iota

	TCP_CLOSED
	TCP_ESTABLISHED

	TCP_LISTEN
	TCP_SYN_SENT
	TCP_SYN_RCVD

	TCP_FIN_WAIT_1
	TCP_FIN_WAIT_2
	TCP_CLOSING
	TCP_TIME_WAIT

	TCP_CLOSE_WAIT
	TCP_LAST_ACK
)

type tcpSock struct {
	state int
	ver   int
	ifidx int
	local net.TCPAddr
	peer  net.TCPAddr

	recvCh chan []byte
	sendCh chan []byte

	acceptCh    chan *tcpSock
	listenQueue map[*tcpSock]struct{}
}

func (sock *tcpSock) Init() (err error) {
	sock.state = TCP_CLOSED
	sock.recvCh = make(chan []byte, 1024)
	sock.sendCh = make(chan []byte, 1024)
	return
}
