// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

// Package tunnel runs WireGuard entirely in userspace inside the process
// (wireguard-go device + gVisor netstack TUN). No TUN device, VPN service
// or administrator rights are needed.
package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"terminalmax.org/wgbridge/forward"
	"terminalmax.org/wgbridge/wgconf"
)

// DefaultMTU is used when the configuration has no MTU.
const DefaultMTU = 1420

// TokenLen is the length of the per-forward authentication token.
const TokenLen = 32

// Stats re-exports wgconf.Stats.
type Stats = wgconf.Stats

// Tunnel is a running userspace WireGuard device.
type Tunnel struct {
	dev  *device.Device
	tnet *netstack.Net

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	hasDNS bool

	mu     sync.Mutex
	closed bool

	// emu guards the error strings. It is separate from mu because the
	// wireguard-go logger may run while mu is held (Rebind, Close).
	emu        sync.Mutex
	lastFwdErr string
	lastDevErr string
}

func (t *Tunnel) setDevErr(s string) {
	t.emu.Lock()
	t.lastDevErr = wgconf.SanitizeASCII(s, 256)
	t.emu.Unlock()
}

func (t *Tunnel) setFwdErr(err error) {
	t.emu.Lock()
	t.lastFwdErr = wgconf.SanitizeASCII(err.Error(), 256)
	t.emu.Unlock()
}

func zero(b []byte) { clear(b) }

// Start brings up a tunnel from conf. Peer endpoint host names are resolved
// with the system resolver (outside the tunnel) if that has not been done.
//
// Start consumes the key material in conf: once the device has been
// configured (or Start has failed) conf.PrivateKey and every PresharedKey
// are zeroed, and so is the UAPI text it built. wireguard-go keeps its own
// copy of the keys for the lifetime of the device.
func Start(conf *wgconf.Config) (*Tunnel, error) {
	if conf == nil {
		return nil, errors.New("tunnel: nil config")
	}
	defer conf.Zero()
	rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := wgconf.ResolveEndpoints(rctx, conf, nil)
	rcancel()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(nil)
	werr := conf.WriteUAPI(buf)
	wipe := func() {
		b := buf.Bytes()
		zero(b[:cap(b)])
		buf.Reset()
	}
	if werr != nil {
		wipe()
		return nil, werr
	}
	addrs := make([]netip.Addr, 0, len(conf.Addresses))
	for _, p := range conf.Addresses {
		addrs = append(addrs, p.Addr())
	}
	mtu := conf.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	tdev, tnet, err := netstack.CreateNetTUN(addrs, conf.DNS, mtu)
	if err != nil {
		wipe()
		return nil, fmt.Errorf("tunnel: create netstack: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &Tunnel{tnet: tnet, ctx: ctx, cancel: cancel, hasDNS: len(conf.DNS) > 0}
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			t.setDevErr(fmt.Sprintf(format, args...))
		},
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	err = dev.IpcSetOperation(bytes.NewReader(buf.Bytes()))
	wipe()
	if err != nil {
		dev.Close()
		cancel()
		return nil, fmt.Errorf("tunnel: configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		cancel()
		return nil, fmt.Errorf("tunnel: bring device up: %w", err)
	}
	t.dev = dev
	return t, nil
}

// OpenForward starts a one-connection loopback forwarder to target
// ("host:port", dialled through the tunnel) and returns its loopback port
// and a random token. The client must send the 32 token bytes as the first
// bytes on the connection, before any other data; otherwise the connection
// is dropped and the target is never dialled.
func (t *Tunnel) OpenForward(target string) (port int, token [TokenLen]byte, err error) {
	host, _, serr := net.SplitHostPort(target)
	if serr != nil {
		return 0, token, errors.New("tunnel: target must be host:port")
	}
	if _, perr := netip.ParseAddr(host); perr != nil && !t.hasDNS {
		return 0, token, errors.New("tunnel: target must be an IP address when the profile has no DNS")
	}
	if _, rerr := rand.Read(token[:]); rerr != nil {
		return 0, [TokenLen]byte{}, fmt.Errorf("tunnel: random token: %w", rerr)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return 0, [TokenLen]byte{}, errors.New("tunnel: closed")
	}
	port, done, err := forward.ListenOnce(t.ctx, t.tnet, target, forward.Options{Token: token[:]})
	if err != nil {
		return 0, [TokenLen]byte{}, err
	}
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		if ferr := <-done; ferr != nil && !errors.Is(ferr, context.Canceled) {
			t.setFwdErr(ferr)
		}
	}()
	return port, token, nil
}

// Stats returns the last handshake time and byte counters, the last
// forwarder error and the last error logged by wireguard-go. It streams the device's IPC output through a parser that
// never stores key lines.
func (t *Tunnel) Stats() (Stats, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	t.emu.Lock()
	fwdErr, devErr := t.lastFwdErr, t.lastDevErr
	t.emu.Unlock()
	if closed {
		return Stats{}, errors.New("tunnel: closed")
	}
	var sw wgconf.StatsWriter
	if err := t.dev.IpcGetOperation(&sw); err != nil {
		return Stats{}, fmt.Errorf("tunnel: ipc get: %w", err)
	}
	st := sw.Stats()
	st.LastForwardError = fwdErr
	st.LastDeviceError = devErr
	return st, nil
}

// Rebind closes and reopens the device's UDP socket (Down then Up). Call it
// after a network change or when the device wakes from sleep so that
// WireGuard re-handshakes immediately. Existing forwarders are unaffected.
func (t *Tunnel) Rebind() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("tunnel: closed")
	}
	if err := t.dev.Down(); err != nil {
		return fmt.Errorf("tunnel: rebind down: %w", err)
	}
	if err := t.dev.Up(); err != nil {
		return fmt.Errorf("tunnel: rebind up: %w", err)
	}
	return nil
}

// Close stops all forwarders and then shuts the device down. It is safe to
// call more than once.
func (t *Tunnel) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()
	t.cancel()
	t.wg.Wait()
	t.dev.Close()
}
