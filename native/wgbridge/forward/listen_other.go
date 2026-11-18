//go:build !windows

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

package forward

import "syscall"

// listenControl is a no-op: on Unix-like systems a bound listening port
// cannot be hijacked by an unprivileged process without SO_REUSEPORT
// cooperation from the owner.
func listenControl(network, address string, c syscall.RawConn) error { return nil }
