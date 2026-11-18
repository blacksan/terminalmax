//go:build windows

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

package forward

import (
	"syscall"
)

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE, defined by winsock as
// ~SO_REUSEADDR. With it, another process cannot bind the same port, even
// one that sets SO_REUSEADDR (which on Windows would let it hijack the
// loopback port).
const soExclusiveAddrUse = ^syscall.SO_REUSEADDR

func listenControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soExclusiveAddrUse, 1)
	}); err != nil {
		return err
	}
	return serr
}
