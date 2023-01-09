package stack

type Sock interface {
	Init() error
	Connect(addr any) error
	Bind(addr any) error
	Listen() error
	Accept() (Sock, error)
	Write(buf []byte) (int, error)
	Read(buf []byte) (int, error)
	Close() error
	Abort() error
}
