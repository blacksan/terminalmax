// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

// Command libwgbridge is built with -buildmode=c-shared and exposes a small
// C ABI around the userspace WireGuard tunnel. Only int32 handles, C strings
// and caller-owned buffers cross the boundary; no Go pointers are retained
// by C and no C pointers are retained by Go.
package main

/*
#include <stdlib.h>
#include <string.h>
static inline const char *wgb_version_str(void) { return "terminalmax-wgbridge/0.3.0"; }
*/
import "C"

import (
	"sync"
	"unsafe"

	"terminalmax.org/wgbridge/tunnel"
	"terminalmax.org/wgbridge/wgconf"
)

// Return codes (negative values are errors).
const (
	errConfig       = -1 // configuration text invalid
	errStart        = -2 // tunnel failed to start
	errBadHandle    = -3 // unknown or closed handle
	errForward      = -4 // forwarder could not be opened / stats / rebind failed
	errBufTooSmall  = -5 // output buffer too small
	errBadArguments = -6 // NULL pointer or non-positive length
)

// maxConfLen bounds the config text accepted by wgbStart.
const maxConfLen = 1 << 20

var (
	mu       sync.Mutex
	tunnels  = map[int32]*tunnel.Tunnel{}
	nextID   int32
	lastErr  string
	lastErrM sync.Mutex
)

func setLastError(s string) {
	lastErrM.Lock()
	lastErr = s
	lastErrM.Unlock()
}

// writeCString copies s into buf (capacity n) NUL-terminated, truncating if
// necessary. Every byte outside printable ASCII (0x20..0x7e) is replaced
// with '?'. It returns the number of bytes written excluding the NUL.
func writeCString(buf *C.char, n C.int, s string) int {
	if buf == nil || n <= 0 {
		return 0
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))
	k := copy(dst[:len(dst)-1], s)
	for i := 0; i < k; i++ {
		if dst[i] < 0x20 || dst[i] > 0x7e {
			dst[i] = '?'
		}
	}
	dst[k] = 0
	return k
}

// failCall records msg as the last error, writes it to errBuf (if any) and
// returns code.
func failCall(code int, errBuf *C.char, errLen C.int, msg string) C.int {
	setLastError(wgconf.SanitizeASCII(msg, 0))
	writeCString(errBuf, errLen, msg)
	return C.int(code)
}

func lookup(h C.int) *tunnel.Tunnel {
	mu.Lock()
	defer mu.Unlock()
	return tunnels[int32(h)]
}

// newHandle stores t under a fresh positive id. Caller holds no locks.
func newHandle(t *tunnel.Tunnel) int32 {
	mu.Lock()
	defer mu.Unlock()
	for {
		nextID++
		if nextID <= 0 { // wrapped
			nextID = 1
		}
		if _, used := tunnels[nextID]; !used {
			tunnels[nextID] = t
			return nextID
		}
	}
}

// wgbStart parses the wg-quick style config in confText and starts a tunnel.
// It returns a handle > 0, or a negative error code. On error a message is
// written to errBuf (if non-NULL) and is also available via wgbLastError.
// The caller should zero its copy of confText afterwards.
//
//export wgbStart
func wgbStart(confText *C.char, errBuf *C.char, errLen C.int) C.int {
	if confText == nil {
		return failCall(errBadArguments, errBuf, errLen, errNullConf.Error())
	}
	n := C.strnlen(confText, C.size_t(maxConfLen+1))
	if n > C.size_t(maxConfLen) {
		return failCall(errConfig, errBuf, errLen, "wgconf: config too large")
	}
	// Parse over the caller's memory instead of copying it with C.GoStringN:
	// a Go copy could never be zeroed. This is safe only because
	// wgconf.Parse must not retain substrings of its input; the string must
	// not be used after this call returns (the caller zeroes the buffer).
	conf, err := wgconf.Parse(unsafe.String((*byte)(unsafe.Pointer(confText)), int(n)))
	if err != nil {
		return failCall(errConfig, errBuf, errLen, err.Error())
	}
	t, err := tunnel.Start(conf)
	if err != nil {
		return failCall(errStart, errBuf, errLen, err.Error())
	}
	id := newHandle(t)
	setLastError("")
	return C.int(id)
}

// wgbOpenForward opens a one-connection loopback forwarder to target
// ("ip:port"; "host:port" only if the profile has DNS servers) and returns
// the 127.0.0.1 port, or a negative error code. tokenOut must point to 32
// writable bytes: on success they receive the random token that the client
// must send as the first 32 bytes on the connection. On error a message is
// written to errBuf (if non-NULL) and is also available via wgbLastError.
//
//export wgbOpenForward
func wgbOpenForward(handle C.int, target *C.char, tokenOut *C.uchar, errBuf *C.char, errLen C.int) C.int {
	if target == nil {
		return failCall(errBadArguments, errBuf, errLen, errNullTarget.Error())
	}
	if tokenOut == nil {
		return failCall(errBadArguments, errBuf, errLen, errNullToken.Error())
	}
	t := lookup(handle)
	if t == nil {
		return failCall(errBadHandle, errBuf, errLen, errBadHandleMsg)
	}
	port, tok, err := t.OpenForward(C.GoString(target))
	if err != nil {
		return failCall(errForward, errBuf, errLen, err.Error())
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(tokenOut)), tunnel.TokenLen)
	copy(dst, tok[:])
	clear(tok[:])
	return C.int(port)
}

// wgbStats writes a JSON object
// {"last_handshake_unix_ms":N,"rx_bytes":N,"tx_bytes":N[,"last_forward_error":"..."]}
// into buf and returns its length, or a negative error code. On error a
// message is written to errBuf (if non-NULL).
//
//export wgbStats
func wgbStats(handle C.int, buf *C.char, length C.int, errBuf *C.char, errLen C.int) C.int {
	if buf == nil || length <= 0 {
		return failCall(errBadArguments, errBuf, errLen, "wgbridge: invalid output buffer")
	}
	t := lookup(handle)
	if t == nil {
		return failCall(errBadHandle, errBuf, errLen, errBadHandleMsg)
	}
	st, err := t.Stats()
	if err != nil {
		return failCall(errForward, errBuf, errLen, err.Error())
	}
	js := st.JSON()
	if len(js)+1 > int(length) {
		return failCall(errBufTooSmall, errBuf, errLen, "wgbridge: stats buffer too small")
	}
	return C.int(writeCString(buf, length, js))
}

// wgbRebind closes and reopens the tunnel's UDP socket so that it
// re-handshakes at once. Call it on network change or when the device wakes
// from sleep. Returns 0 or a negative error code (message via wgbLastError).
//
//export wgbRebind
func wgbRebind(handle C.int) C.int {
	t := lookup(handle)
	if t == nil {
		return failCall(errBadHandle, nil, 0, errBadHandleMsg)
	}
	if err := t.Rebind(); err != nil {
		return failCall(errForward, nil, 0, err.Error())
	}
	return 0
}

// wgbStop closes the tunnel and its forwarders. Unknown handles are ignored.
//
//export wgbStop
func wgbStop(handle C.int) {
	mu.Lock()
	t := tunnels[int32(handle)]
	delete(tunnels, int32(handle))
	mu.Unlock()
	if t != nil {
		t.Close()
	}
}

// wgbLastError copies the most recent error message into buf and returns
// its length (0 if none).
//
//export wgbLastError
func wgbLastError(buf *C.char, length C.int) C.int {
	lastErrM.Lock()
	s := lastErr
	lastErrM.Unlock()
	return C.int(writeCString(buf, length, s))
}

// wgbVersion returns a static, NUL-terminated version string. The caller
// must not free it.
//
//export wgbVersion
func wgbVersion() *C.char {
	return (*C.char)(unsafe.Pointer(C.wgb_version_str()))
}

func main() {}
