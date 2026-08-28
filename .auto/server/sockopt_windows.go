package main

import "syscall"

const socketBufferSize = 2 << 20 // 2MB SO_RCVBUF/SO_SNDBUF: high-BDP links + loopback need big windows

// tuneSocket raises the TCP socket buffers on a fresh connection. Windows doubles
// the requested value internally, so 2MB request -> ~4MB effective; memory stays
// bounded because the runtime recycles a fixed pool of connections.
//
// Best-effort by design: net.Dialer.Control fails the whole dial if it returns
// an error, so a rejected setsockopt (hardened kernel, container, unsupported
// platform) must NOT break the benchmark — big buffers are an optimization, not
// a requirement.
func tuneSocket(raw syscall.RawConn) error {
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, socketBufferSize)
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, socketBufferSize)
	})
	return nil
}
