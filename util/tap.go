package util

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	devPath = "/dev/net/tun"
	ifrSize = unix.IFNAMSIZ + 64
)

func OpenTap(ifaceName string) (*os.File, error) {
	// open tap device
	fd, err := unix.Open(devPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	// set tap interface
	var ifr [ifrSize]byte
	iface := []byte(ifaceName)
	if len(iface) >= unix.IFNAMSIZ {
		return nil, errors.New("tap interface overflow")
	}
	copy(ifr[:], iface)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TAP | unix.IFF_NO_PI
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return nil, errno
	}

	// set nonblock
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}

	// create tap
	return os.NewFile(uintptr(fd), devPath), nil
}
