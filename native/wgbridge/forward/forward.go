// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

// Package forward implements a one-shot loopback TCP forwarder: it listens
// on 127.0.0.1 on a random port, accepts exactly one connection, closes the
// listener, dials a target through a Dialer (for example a userspace
// WireGuard netstack) and relays bytes in both directions.
package forward

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Dialer opens outbound connections, e.g. through a WireGuard tunnel.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Options tune ListenOnce. Zero values select defaults.
type Options struct {
	// AcceptTimeout bounds the wait for the single client. Default 5s.
	AcceptTimeout time.Duration
	// DialTimeout bounds the dial to the target. Default 20s.
	DialTimeout time.Duration
	// Token, if non-empty, must be the first bytes the client sends. It is
	// checked (in constant time) before the target is dialled; on mismatch,
	// short read or timeout the connection is closed and the dialer is
	// never called. ListenOnce keeps its own copy.
	Token []byte
}

const (
	defaultAcceptTimeout = 5 * time.Second
	defaultDialTimeout   = 20 * time.Second
)

// authTimeout bounds how long the client may take to send the token. It is a
// variable only so that tests can shorten it.
var authTimeout = 5 * time.Second

// errAuth is returned for every kind of token failure.
var errAuth = errors.New("forward: client failed authentication")

// quote renders a user-supplied string for an error message.
func quote(s string) string {
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	return strconv.QuoteToASCII(s)
}

type closeWriter interface{ CloseWrite() error }

// ListenOnce opens a loopback listener and returns its port. The returned
// channel receives exactly one value (nil on a clean finish) and is then
// closed, once the forwarder has finished and all sockets are closed.
// Cancelling ctx aborts the forwarder.
func ListenOnce(ctx context.Context, d Dialer, target string, opts Options) (port int, done <-chan error, err error) {
	if d == nil {
		return 0, nil, errors.New("forward: nil dialer")
	}
	if _, _, serr := net.SplitHostPort(target); serr != nil {
		return 0, nil, fmt.Errorf("forward: invalid target %s: %w", quote(target), serr)
	}
	if opts.AcceptTimeout <= 0 {
		opts.AcceptTimeout = defaultAcceptTimeout
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = defaultDialTimeout
	}
	opts.Token = append([]byte(nil), opts.Token...)
	lc := net.ListenConfig{Control: listenControl}
	l, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("forward: listen: %w", err)
	}
	ln := l.(*net.TCPListener)
	port = ln.Addr().(*net.TCPAddr).Port
	ch := make(chan error, 1)
	go func() {
		ch <- run(ctx, ln, d, target, opts)
		close(ch)
	}()
	return port, ch, nil
}

func run(ctx context.Context, ln *net.TCPListener, d Dialer, target string, opts Options) error {
	defer ln.Close() // guaranteed even on early return
	defer clear(opts.Token)

	_ = ln.SetDeadline(time.Now().Add(opts.AcceptTimeout))
	stopAccept := context.AfterFunc(ctx, func() { ln.Close() })
	client, err := ln.Accept()
	stopAccept()
	// Whatever happened, no further connections are accepted.
	ln.Close()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("forward: no client connected within %s", opts.AcceptTimeout)
		}
		return fmt.Errorf("forward: accept: %w", err)
	}
	defer client.Close()

	if len(opts.Token) > 0 {
		if err := authenticate(ctx, client, opts.Token); err != nil {
			return err
		}
	}

	dctx, cancel := context.WithTimeout(ctx, opts.DialTimeout)
	remote, err := d.DialContext(dctx, "tcp", target)
	cancel()
	if err != nil {
		return fmt.Errorf("forward: dial %s: %w", quote(target), err)
	}
	defer remote.Close()

	stop := context.AfterFunc(ctx, func() {
		client.Close()
		remote.Close()
	})
	defer stop()

	errc := make(chan error, 2)
	go func() { errc <- pipe(remote, client) }()
	go func() { errc <- pipe(client, remote) }()

	var first error
	for i := 0; i < 2; i++ {
		if e := <-errc; e != nil {
			if first == nil {
				first = e
			}
			// Abort the other direction as well.
			client.Close()
			remote.Close()
		}
	}
	if ctx.Err() != nil {
		// The relay was cut short by cancellation: report that, not the
		// "use of closed connection" noise it caused.
		return ctx.Err()
	}
	return first
}

// authenticate reads len(token) bytes from c within authTimeout and compares
// them with token in constant time. The read deadline is cleared on success.
func authenticate(ctx context.Context, c net.Conn, token []byte) error {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	_ = c.SetReadDeadline(time.Now().Add(authTimeout))
	got := make([]byte, len(token))
	defer clear(got)
	if _, err := io.ReadFull(c, got); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errAuth
	}
	if subtle.ConstantTimeCompare(got, token) != 1 {
		return errAuth
	}
	_ = c.SetReadDeadline(time.Time{})
	return nil
}

// pipe copies src to dst, then half-closes dst's write side when possible.
func pipe(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)
	if err != nil {
		return err
	}
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	} else {
		dst.Close()
	}
	return nil
}
