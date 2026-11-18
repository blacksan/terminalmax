// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

package forward

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// netDialer dials with the standard library; used as the "tunnel".
type netDialer struct{ calls int }

func (d *netDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.calls++
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

type failDialer struct{}

func (failDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("boom")
}

// echoServer echoes everything until the peer half-closes, then closes.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func wait(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for forwarder")
		return nil
	}
}

func addr(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

func TestEchoAndHalfClose(t *testing.T) {
	target := echoServer(t)
	d := &netDialer{}
	port, done, err := ListenOnce(context.Background(), d, target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte("terminalmax"), 50000) // ~550 KB
	go func() {
		c.Write(payload)
		c.(*net.TCPConn).CloseWrite() // half-close: server must still send back everything
	}()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes want %d", len(got), len(payload))
	}
	if err := wait(t, done); err != nil {
		t.Fatalf("done: %v", err)
	}
}

func TestSecondConnectionRefused(t *testing.T) {
	target := echoServer(t)
	port, done, err := ListenOnce(context.Background(), &netDialer{}, target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Round trip proves the first connection was accepted (and the listener closed).
	c.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if c2, err := net.DialTimeout("tcp", addr(port), time.Second); err == nil {
		c2.Close()
		t.Fatal("second connection was accepted")
	}
	c.Close()
	if err := wait(t, done); err != nil {
		t.Logf("done (informational): %v", err)
	}
}

func TestAcceptTimeout(t *testing.T) {
	d := &netDialer{}
	port, done, err := ListenOnce(context.Background(), d, "127.0.0.1:9", Options{AcceptTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := wait(t, done); err == nil {
		t.Fatal("expected timeout error")
	}
	if d.calls != 0 {
		t.Fatal("dialer must not be called")
	}
	if c, err := net.DialTimeout("tcp", addr(port), time.Second); err == nil {
		c.Close()
		t.Fatal("listener still open after timeout")
	}
}

func TestDialFailureClosesClient(t *testing.T) {
	port, done, err := ListenOnce(context.Background(), failDialer{}, "10.0.0.1:22", Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || (err != io.EOF && !isReset(err)) {
		t.Fatalf("expected EOF/reset, got n=%d err=%v", n, err)
	}
	if err := wait(t, done); err == nil {
		t.Fatal("expected dial error")
	}
}

func isReset(err error) bool {
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func TestContextCancelBeforeAccept(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	port, done, err := ListenOnce(ctx, &netDialer{}, "127.0.0.1:9", Options{})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := wait(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if c, err := net.DialTimeout("tcp", addr(port), time.Second); err == nil {
		c.Close()
		t.Fatal("listener still open")
	}
}

func TestContextCancelDuringRelay(t *testing.T) {
	target := echoServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	port, done, err := ListenOnce(ctx, &netDialer{}, target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := net.Dial("tcp", addr(port))
	defer c.Close()
	c.Write([]byte("x"))
	io.ReadFull(c, make([]byte, 1))
	cancel()
	wait(t, done) // must terminate
}

func TestInvalidArgs(t *testing.T) {
	if _, _, err := ListenOnce(context.Background(), &netDialer{}, "no-port", Options{}); err == nil {
		t.Fatal("expected invalid target error")
	}
	if _, _, err := ListenOnce(context.Background(), nil, "1.2.3.4:5", Options{}); err == nil {
		t.Fatal("expected nil dialer error")
	}
}

var testToken = []byte("0123456789abcdef0123456789abcdef")

func TestTokenCorrectRelays(t *testing.T) {
	target := echoServer(t)
	d := &netDialer{}
	port, done, err := ListenOnce(context.Background(), d, target, Options{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Token and payload in a single write: the payload must not be lost.
	msg := []byte("after the token")
	c.Write(append(append([]byte{}, testToken...), msg...))
	c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("got %q err %v", got, err)
	}
	if err := wait(t, done); err != nil {
		t.Fatalf("done: %v", err)
	}
}

func expectAuthFailure(t *testing.T, d *netDialer, done <-chan error, c net.Conn) {
	t.Helper()
	err := wait(t, done)
	if err == nil || err.Error() != "forward: client failed authentication" {
		t.Fatalf("got %v", err)
	}
	if d.calls != 0 {
		t.Fatal("dialer was called despite failed authentication")
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || !isReset(err) {
		t.Fatalf("expected closed connection, n=%d err=%v", n, err)
	}
}

func TestTokenWrongNeverDials(t *testing.T) {
	d := &netDialer{}
	port, done, err := ListenOnce(context.Background(), d, "127.0.0.1:9", Options{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	bad := append([]byte{}, testToken...)
	bad[len(bad)-1] ^= 1
	c.Write(bad)
	expectAuthFailure(t, d, done, c)
}

func TestTokenNotSentTimesOut(t *testing.T) {
	old := authTimeout
	authTimeout = 200 * time.Millisecond
	defer func() { authTimeout = old }()
	d := &netDialer{}
	port, done, err := ListenOnce(context.Background(), d, "127.0.0.1:9", Options{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	expectAuthFailure(t, d, done, c)
}

func TestTokenShort(t *testing.T) {
	d := &netDialer{}
	port, done, err := ListenOnce(context.Background(), d, "127.0.0.1:9", Options{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(testToken[:10])
	c.(*net.TCPConn).CloseWrite()
	expectAuthFailure(t, d, done, c)
}

func TestTokenCopiedAndDefaultAcceptTimeout(t *testing.T) {
	tok := append([]byte{}, testToken...)
	port, done, err := ListenOnce(context.Background(), &netDialer{}, "127.0.0.1:9", Options{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	clear(tok) // caller zeroing its copy must not break the forwarder's check
	c, _ := net.Dial("tcp", addr(port))
	defer c.Close()
	c.Write(testToken)
	// A correct token proceeds to dial 127.0.0.1:9, which fails (not an auth error).
	if err := wait(t, done); err == nil || errors.Is(err, errAuth) {
		t.Fatalf("got %v", err)
	}
	if defaultAcceptTimeout != 5*time.Second {
		t.Fatal("default accept timeout must be 5s")
	}
}

func TestCancelDuringRelayReturnsCtxErr(t *testing.T) {
	target := echoServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	port, done, err := ListenOnce(ctx, &netDialer{}, target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := net.Dial("tcp", addr(port))
	defer c.Close()
	c.Write([]byte("x"))
	io.ReadFull(c, make([]byte, 1))
	cancel()
	if err := wait(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
