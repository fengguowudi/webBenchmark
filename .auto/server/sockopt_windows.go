package main

import "syscall"

const socketBufferSize = 2 << 20 // 4MB SO_RCVBUF/SO_SNDBUF: high-BDP links + loopback need big windows

// tuneSocket raises the TCP socket buffers on a fresh connection. Windows doubles
// the requested value internally, so 4MB request -> ~8MB effective; memory stays
// bounded because the runtime recycles a fixed pool of connections.
func tuneSocket(raw syscall.RawConn) error {
	var setErr error
	_ = raw.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, socketBufferSize); err != nil {
			setErr = err
			return
		}
		if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, socketBufferSize); err != nil {
			setErr = err
			return
		}
	})
	return setErr
}
