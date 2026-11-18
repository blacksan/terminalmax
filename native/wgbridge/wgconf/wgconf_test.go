// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

package wgconf

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func b64(fill byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return base64.StdEncoding.EncodeToString(b)
}

func hex32(fill byte) string {
	return strings.Repeat(strings.ToLower(string("0123456789abcdef"[fill>>4]))+string("0123456789abcdef"[fill&15]), 32)
}

func goodConf() string {
	return "[Interface]\nPrivateKey = " + b64(1) + "\nAddress = 10.0.0.2/32, fd00::2/128\nDNS = 10.0.0.1, example.lan\nMTU = 1380\nListenPort = 51820 # comment\n\n" +
		"[Peer]\nPublicKey = " + b64(2) + "\nPresharedKey = " + b64(3) + "\nAllowedIPs = 10.0.0.0/24, 192.168.1.7\nEndpoint = 203.0.113.5:51820\nPersistentKeepalive = 25\n"
}

func TestParseGood(t *testing.T) {
	c, err := Parse(goodConf())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Addresses) != 2 || c.Addresses[0] != netip.MustParsePrefix("10.0.0.2/32") {
		t.Fatalf("addresses: %v", c.Addresses)
	}
	if len(c.DNS) != 1 || c.DNS[0] != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("dns: %v", c.DNS)
	}
	if c.MTU != 1380 || c.ListenPort != 51820 {
		t.Fatalf("mtu/port: %d %d", c.MTU, c.ListenPort)
	}
	p := c.Peers[0]
	if !p.HasPSK || p.PersistentKeepalive != 25 || len(p.AllowedIPs) != 2 {
		t.Fatalf("peer: %+v", p)
	}
	if p.AllowedIPs[1] != netip.MustParsePrefix("192.168.1.7/32") {
		t.Fatalf("bare ip: %v", p.AllowedIPs[1])
	}
	if p.ResolvedEndpoint != netip.MustParseAddrPort("203.0.113.5:51820") {
		t.Fatalf("endpoint: %v", p.ResolvedEndpoint)
	}
}

func TestUAPI(t *testing.T) {
	c, err := Parse(goodConf())
	if err != nil {
		t.Fatal(err)
	}
	u, err := c.UAPI()
	if err != nil {
		t.Fatal(err)
	}
	want := "private_key=" + hex32(1) + "\n" +
		"listen_port=51820\n" +
		"replace_peers=true\n" +
		"public_key=" + hex32(2) + "\n" +
		"preshared_key=" + hex32(3) + "\n" +
		"endpoint=203.0.113.5:51820\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=10.0.0.0/24\n" +
		"allowed_ip=192.168.1.7/32\n"
	if u != want {
		t.Fatalf("got:\n%s\nwant:\n%s", u, want)
	}
}

func TestIPv6Endpoint(t *testing.T) {
	txt := strings.Replace(goodConf(), "203.0.113.5:51820", "[2001:db8::1]:443", 1)
	c, err := Parse(txt)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := c.UAPI()
	if !strings.Contains(u, "endpoint=[2001:db8::1]:443\n") {
		t.Fatalf("uapi: %s", u)
	}
}

func TestResolveEndpoints(t *testing.T) {
	txt := strings.Replace(goodConf(), "203.0.113.5:51820", "vpn.example.org:51821", 1)
	c, err := Parse(txt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.UAPI(); err == nil {
		t.Fatal("expected unresolved error")
	}
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "vpn.example.org" {
			t.Fatalf("host %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("2001:db8::9"), netip.MustParseAddr("198.51.100.4")}, nil
	}
	if err := ResolveEndpoints(context.Background(), c, lookup); err != nil {
		t.Fatal(err)
	}
	u, err := c.UAPI()
	if err != nil || !strings.Contains(u, "endpoint=198.51.100.4:51821\n") {
		t.Fatalf("uapi %q err %v", u, err)
	}

	c2, _ := Parse(txt)
	fail := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }
	if err := ResolveEndpoints(context.Background(), c2, fail); err == nil {
		t.Fatal("expected lookup error")
	}
	empty := func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	if err := ResolveEndpoints(context.Background(), c2, empty); err == nil {
		t.Fatal("expected empty-result error")
	}
}

func TestParseErrors(t *testing.T) {
	good := goodConf()
	tests := []struct{ name, text, wantSub string }{
		{"empty", "", "missing [Interface]"},
		{"no private key", strings.Replace(good, "PrivateKey = "+b64(1), "MTU = 1400", 1), "PrivateKey is required"},
		{"bad base64", strings.Replace(good, b64(1), "!!!notbase64!!!", 1), "PrivateKey is not valid base64"},
		{"short key", strings.Replace(good, b64(2), base64.StdEncoding.EncodeToString([]byte("short")), 1), "PublicKey must decode to 32 bytes"},
		{"no address", strings.Replace(good, "Address = 10.0.0.2/32, fd00::2/128\n", "", 1), "Address is required"},
		{"bad address", strings.Replace(good, "10.0.0.2/32", "10.0.0.999/32", 1), "invalid Address"},
		{"bad mtu", strings.Replace(good, "MTU = 1380", "MTU = 10", 1), "MTU out of range"},
		{"mtu nan", strings.Replace(good, "MTU = 1380", "MTU = big", 1), "MTU is not a number"},
		{"bad port", strings.Replace(good, "ListenPort = 51820", "ListenPort = 70000", 1), "ListenPort out of range"},
		{"no peers", good[:strings.Index(good, "[Peer]")], "at least one [Peer]"},
		{"peer no pubkey", good[:strings.Index(good, "[Peer]")] + "[Peer]\nAllowedIPs = 10.0.0.0/24\n", "PublicKey is required"},
		{"bad allowedips", strings.Replace(good, "192.168.1.7", "nonsense", 1), "invalid AllowedIPs"},
		{"endpoint no port", strings.Replace(good, "203.0.113.5:51820", "203.0.113.5", 1), "Endpoint must be"},
		{"endpoint bad port", strings.Replace(good, "203.0.113.5:51820", "host:0", 1), "port must be"},
		{"endpoint v6 unbracketed", strings.Replace(good, "203.0.113.5:51820", "2001:db8::1:51820", 1), "Endpoint must be"},
		{"bad keepalive", strings.Replace(good, "PersistentKeepalive = 25", "PersistentKeepalive = -5", 1), "out of range"},
		{"script hook", strings.Replace(good, "MTU = 1380", "PostUp = iptables -A x", 1), "script hooks"},
		{"unknown iface key", strings.Replace(good, "MTU = 1380", "Bogus = 1", 1), "unknown [Interface] key"},
		{"unknown peer key", good + "Bogus = 1\n", "unknown [Peer] key"},
		{"unknown section", "[Foo]\n", "unknown section"},
		{"key outside section", "PrivateKey = x\n", "outside any section"},
		{"no equals", "[Interface]\njunk\n", "expected key = value"},
		{"dup interface", good + "[Interface]\n", "duplicate [Interface]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.text)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
			for _, secret := range []string{b64(1), b64(2), b64(3)} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks key material: %q", err)
				}
			}
		})
	}
}

func TestKeepaliveOffAndNoEndpoint(t *testing.T) {
	txt := "[Interface]\nPrivateKey=" + b64(1) + "\nAddress=10.1.1.1\n[Peer]\nPublicKey=" + b64(2) + "\nAllowedIPs=0.0.0.0/0\nPersistentKeepalive=off\n"
	c, err := Parse(txt)
	if err != nil {
		t.Fatal(err)
	}
	u, err := c.UAPI()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u, "endpoint=") || strings.Contains(u, "persistent_keepalive") || strings.Contains(u, "listen_port") {
		t.Fatalf("unexpected lines: %s", u)
	}
}

func TestParseIpcStats(t *testing.T) {
	in := "private_key=aa\nlisten_port=1\npublic_key=01\nlast_handshake_time_sec=100\nlast_handshake_time_nsec=5\ntx_bytes=10\nrx_bytes=20\n" +
		"public_key=02\nlast_handshake_time_sec=200\nlast_handshake_time_nsec=7\ntx_bytes=1\nrx_bytes=2\nerrno=0\n"
	st := ParseIpcStats(in)
	if st.RxBytes != 22 || st.TxBytes != 11 {
		t.Fatalf("bytes: %+v", st)
	}
	if !st.LastHandshake.Equal(time.Unix(200, 7)) {
		t.Fatalf("hs: %v", st.LastHandshake)
	}
	if got := ParseIpcStats("public_key=01\nlast_handshake_time_sec=0\n").LastHandshake; !got.IsZero() {
		t.Fatalf("expected zero, got %v", got)
	}
	if j := (Stats{RxBytes: 2, TxBytes: 1}).JSON(); j != `{"last_handshake_unix_ms":0,"rx_bytes":2,"tx_bytes":1}` {
		t.Fatalf("json %s", j)
	}
}

func TestNoKeyMaterialInErrors(t *testing.T) {
	good := goodConf()
	k1, k2, k3 := b64(1), b64(2), b64(3)
	// A realistic-looking random key (not a repeated byte) as well.
	rnd := base64.StdEncoding.EncodeToString([]byte("0123456789abcdefghijklmnopqrstuv"))
	tests := []struct {
		name, text, key string
	}{
		{"PrivateKey missing equals", strings.Replace(good, "PrivateKey = "+k1, "PrivateKey "+k1, 1), k1},
		{"PrivateKey colon", strings.Replace(good, "PrivateKey = "+k1, "PrivateKey: "+k1, 1), k1},
		{"PresharedKey missing equals", strings.Replace(good, "PresharedKey = "+k3, "PresharedKey "+k3, 1), k3},
		{"PresharedKey colon", strings.Replace(good, "PresharedKey = "+k3, "PresharedKey: "+k3, 1), k3},
		{"PublicKey missing equals", strings.Replace(good, "PublicKey = "+k2, "PublicKey "+k2, 1), k2},
		{"key in Address", strings.Replace(good, "10.0.0.2/32", rnd, 1), rnd},
		{"key in AllowedIPs", strings.Replace(good, "192.168.1.7", rnd, 1), rnd},
		{"key in AllowedIPs with slash", strings.Replace(good, "192.168.1.7", rnd+"/32", 1), rnd},
		{"key in Endpoint", strings.Replace(good, "203.0.113.5:51820", rnd, 1), rnd},
		{"key in Endpoint port", strings.Replace(good, "203.0.113.5:51820", "h:"+rnd, 1), rnd},
		{"key in MTU", strings.Replace(good, "1380", rnd, 1), rnd},
		{"key in ListenPort", strings.Replace(good, "51820 #", rnd+" #", 1), rnd},
		{"key in Keepalive", strings.Replace(good, "PersistentKeepalive = 25", "PersistentKeepalive = "+rnd, 1), rnd},
		{"key as section", good + "[" + rnd + "]\n", rnd},
		{"key as line", good + rnd + "\n", rnd},
		{"key as option name", good + rnd + " = 1\n", rnd},
		{"key as unknown peer value", good + "Bogus = " + rnd + "\n", rnd},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.text)
			if err == nil {
				t.Fatal("expected error")
			}
			e := strings.ToLower(err.Error())
			if strings.Contains(e, strings.ToLower(tc.key[:20])) {
				t.Fatalf("error leaks key material: %q", err)
			}
		})
	}
}

func TestSafeQuote(t *testing.T) {
	if got := safeQuote(b64(9)); got != "<redacted key-like value>" {
		t.Fatalf("got %q", got)
	}
	if got := safeQuote("  " + b64(9) + " "); got != "<redacted key-like value>" {
		t.Fatalf("got %q", got)
	}
	if got := safeQuote("a\nb\u00e9"); got != `"a\nb\u00e9"` {
		t.Fatalf("got %q", got)
	}
	if got := safeQuote(strings.Repeat("x ", 50)); len(got) != 64+3+2 {
		t.Fatalf("len %d: %q", len(got), got)
	}
	if err := unknownKey("[Peer]", "bogus"); err.Error() != `unknown [Peer] key "bogus"` {
		t.Fatal(err)
	}
	if err := unknownKey("[Peer]", "bog us"); !strings.Contains(err.Error(), "malformed") {
		t.Fatal(err)
	}
}

func TestResolveErrorsDoNotEchoRawHost(t *testing.T) {
	rnd := base64.StdEncoding.EncodeToString([]byte("0123456789abcdefghijklmnopqrstuv"))
	txt := strings.Replace(goodConf(), "203.0.113.5:51820", rnd[:43]+":51820", 1) // not key-like, short host
	c, err := Parse(txt)
	if err != nil {
		t.Fatal(err)
	}
	fail := func(_ context.Context, host string) ([]netip.Addr, error) {
		return nil, errors.New("lookup " + host + ": no such host")
	}
	err = ResolveEndpoints(context.Background(), c, fail)
	if err == nil || strings.Count(err.Error(), rnd[:43]) > 1 {
		t.Fatalf("host repeated in %v", err)
	}
}

func TestBOMAndSize(t *testing.T) {
	if _, err := Parse("\xef\xbb\xbf" + goodConf()); err != nil {
		t.Fatalf("BOM: %v", err)
	}
	big := goodConf() + "#" + strings.Repeat("x", 1<<20)
	if _, err := Parse(big); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("got %v", err)
	}
}

func TestWriteUAPIMatchesAndZero(t *testing.T) {
	c, _ := Parse(goodConf())
	var b bytes.Buffer
	if err := c.WriteUAPI(&b); err != nil {
		t.Fatal(err)
	}
	u, _ := c.UAPI()
	if b.String() != u || !strings.HasPrefix(u, "private_key="+hex32(1)) {
		t.Fatalf("mismatch:\n%s", u)
	}
	c.Zero()
	if !c.PrivateKey.IsZero() || !c.Peers[0].PresharedKey.IsZero() {
		t.Fatal("keys not zeroed")
	}
}

func TestStatsWriterStreaming(t *testing.T) {
	in := "private_key=" + hex32(1) + "\nlisten_port=1\npublic_key=01\npreshared_key=" + hex32(3) +
		"\nlast_handshake_time_sec=100\nlast_handshake_time_nsec=5\ntx_bytes=10\nrx_bytes=20\n" +
		"public_key=02\nlast_handshake_time_sec=200\nlast_handshake_time_nsec=7\ntx_bytes=1\nrx_bytes=2\nerrno=0\n"
	var w StatsWriter
	// Feed one byte at a time to exercise chunk boundaries.
	for i := 0; i < len(in); i++ {
		if _, err := w.Write([]byte{in[i]}); err != nil {
			t.Fatal(err)
		}
	}
	st := w.Stats()
	if st.RxBytes != 22 || st.TxBytes != 11 || !st.LastHandshake.Equal(time.Unix(200, 7)) {
		t.Fatalf("%+v", st)
	}
	// Stats() on a fresh writer is zero.
	var z StatsWriter
	if s := z.Stats(); !s.LastHandshake.IsZero() || s.RxBytes != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestStatsJSONForwardError(t *testing.T) {
	// The e-acute is two UTF-8 bytes (two '?'), the newline one.
	j := (Stats{LastForwardError: "bad \"x\"\\ \u00e9\n"}).JSON()
	if j != `{"last_handshake_unix_ms":0,"rx_bytes":0,"tx_bytes":0,"last_forward_error":"bad 'x'' ???"}` {
		t.Fatalf("got %s", j)
	}
}
