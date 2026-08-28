//go:build !windows && !linux

package main

import "syscall"

// tuneSocket is a no-op on platforms without the socket-buffer tuning files
// (windows, linux). The tool still works everywhere; it just doesn't get the
// big SO_RCVBUF/SO_SNDBUF boost. Best-effort by design.
func tuneSocket(raw syscall.RawConn) error {
	return nil
}
