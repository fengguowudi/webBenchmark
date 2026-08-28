package main

import "syscall"

const socketBufferSize = 2 << 20 // 4MB SO_RCVBUF/SO_SNDBUF: high-BDP links + loopback need big windows

// tuneSocket raises the TCP socket buffers on a fresh connection.
func tuneSocket(raw syscall.RawConn) error {
	var setErr error
	_ = raw.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, socketBufferSize); err != nil {
			setErr = err
			return
		}
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, socketBufferSize); err != nil {
			setErr = err
			return
		}
	})
	return setErr
}
