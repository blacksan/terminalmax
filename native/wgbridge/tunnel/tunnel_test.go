// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

package tunnel

import (
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"terminalmax.org/wgbridge/wgconf"
)

func genKeyPair(t *testing.T) (priv, pub wgconf.Key) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(priv[:], k.Bytes())
	copy(pub[:], k.PublicKey().Bytes())
	return
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestForwardEchoThroughTunnel(t *testing.T) {
	routerPriv, routerPub := genKeyPair(t)
	clientPriv, clientPub := genKeyPair(t)

	var (
		router, client *Tunnel
		port           int
	)
	// The UDP port is picked by binding and releasing it, which can race
	// with other processes: retry with a fresh port if Start fails. Start
	// zeroes the keys in its config, so the configs are rebuilt each time.
	for attempt := 1; ; attempt++ {
		port = freeUDPPort(t)
		routerConf := &wgconf.Config{
			PrivateKey: routerPriv,
			Addresses:  []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32")},
			ListenPort: port,
			Peers: []wgconf.Peer{{
				PublicKey:  clientPub,
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
			}},
		}
		r, err := Start(routerConf)
		if err == nil {
			router = r
			break
		}
		if attempt >= 5 {
			t.Fatalf("router start failed %d times: %v", attempt, err)
		}
		t.Logf("router start attempt %d: %v (retrying with a new port)", attempt, err)
	}
	defer router.Close()

	clientConf := &wgconf.Config{
		PrivateKey: clientPriv,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
		Peers: []wgconf.Peer{{
			PublicKey:           routerPub,
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32")},
			EndpointHost:        "127.0.0.1",
			EndpointPort:        uint16(port),
			ResolvedEndpoint:    netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)),
			PersistentKeepalive: 1,
		}},
	}
	client, err := Start(clientConf)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if !clientConf.PrivateKey.IsZero() {
		t.Fatal("Start must zero the private key in the config")
	}

	ln, err := router.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 99, 0, 1), Port: 2222})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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

	lport, token, err := client.OpenForward("10.99.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(lport)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write(token[:]); err != nil { // the token must come first
		t.Fatal(err)
	}

	msg := []byte("hello through wireguard")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: %q", got)
	}

	st, err := client.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.LastHandshake.IsZero() || st.TxBytes == 0 || st.RxBytes == 0 {
		t.Fatalf("unexpected stats: %+v", st)
	}

	// Second connection to the single-use listener must fail.
	if c2, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(lport)), time.Second); err == nil {
		c2.Close()
		t.Fatal("forward listener accepted a second connection")
	}

	client.Close()
	client.Close() // idempotent
	if _, _, err := client.OpenForward("10.99.0.1:2222"); err == nil {
		t.Fatal("OpenForward after Close should fail")
	}
	if err := client.Rebind(); err == nil {
		t.Fatal("Rebind after Close should fail")
	}
}

func TestRebindKeepsWorking(t *testing.T) {
	priv, _ := genKeyPair(t)
	_, peerPub := genKeyPair(t)
	tn, err := Start(&wgconf.Config{
		PrivateKey: priv,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.99.1.2/32")},
		Peers:      []wgconf.Peer{{PublicKey: peerPub, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.1.1/32")}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	if err := tn.Rebind(); err != nil {
		t.Fatal(err)
	}
	if _, err := tn.Stats(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenForwardNeedsIPWithoutDNS(t *testing.T) {
	priv, _ := genKeyPair(t)
	_, peerPub := genKeyPair(t)
	tn, err := Start(&wgconf.Config{
		PrivateKey: priv,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.99.2.2/32")},
		Peers:      []wgconf.Peer{{PublicKey: peerPub, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.2.1/32")}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	if _, _, err := tn.OpenForward("example.com:22"); err == nil {
		t.Fatal("expected error for a host name without DNS")
	}
}
