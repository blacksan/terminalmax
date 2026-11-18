// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

package wgconf

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
	if got := safeQuote(strings.Repeat(". ", 50)); len(got) != 64+3+2 {
		t.Fatalf("len %d: %q", len(got), got)
	}
	if err := unknownKey("[Peer]", "bogus"); err.Error() != `unknown [Peer] key "bogus"` {
		t.Fatal(err)
	}
	if err := unknownKey("[Peer]", "bog us"); !strings.Contains(err.Error(), "malformed") {
		t.Fatal(err)
	}
}

func TestResolveErrorsDoNotEchoResolverText(t *testing.T) {
	txt := strings.Replace(goodConf(), "203.0.113.5:51820", "Vpn.Example.ORG:51820", 1)
	reasons := []struct {
		name string
		err  error
		want string
	}{
		{"plain", errors.New("SECRET-RESOLVER-TEXT lookup vpn.example.org"), "lookup failed"},
		{"not found", &net.DNSError{Err: "SECRET-RESOLVER-TEXT", Name: "vpn.example.org", IsNotFound: true}, "no such host"},
		{"timeout", &net.DNSError{Err: "SECRET-RESOLVER-TEXT", Name: "vpn.example.org", IsTimeout: true}, "timeout"},
		{"deadline", fmt.Errorf("SECRET-RESOLVER-TEXT: %w", context.DeadlineExceeded), "timeout"},
		{"temporary", &net.DNSError{Err: "SECRET-RESOLVER-TEXT", Name: "vpn.example.org", IsTemporary: true}, "temporary DNS failure"},
	}
	for _, tc := range reasons {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse(txt)
			if err != nil {
				t.Fatal(err)
			}
			fail := func(context.Context, string) ([]netip.Addr, error) { return nil, tc.err }
			err = ResolveEndpoints(context.Background(), c, fail)
			if err == nil || !strings.HasSuffix(err.Error(), ": "+tc.want) || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestResolveErrorLowercasedKeyHost(t *testing.T) {
	key := randKey(t)
	for _, enc := range keyEncodings(" ") {
		t.Run(enc.name, func(t *testing.T) {
			c, err := Parse(buildConf("\n", " ", map[string]string{"endpoint": enc.val(key) + ":51820"}, nil))
			if err != nil {
				t.Skipf("endpoint rejected by Parse: %v", err)
			}
			fail := func(_ context.Context, host string) ([]netip.Addr, error) {
				return nil, errors.New("lookup " + strings.ToLower(host) + ": no such host")
			}
			err = ResolveEndpoints(context.Background(), c, fail)
			if err == nil {
				t.Fatal("expected error")
			}
			assertNoKeyRun(t, err.Error(), enc.val(key))
			_, err = c.UAPI()
			if err == nil {
				t.Fatal("expected unresolved error")
			}
			assertNoKeyRun(t, err.Error(), enc.val(key))
		})
	}
}

type keyEnc struct {
	name string
	val  func(k []byte) string
}

// keyEncodings lists the ways a user might have pasted a key; sep is used
// for the "split" variants.
func keyEncodings(sep string) []keyEnc {
	std := func(k []byte) string { return base64.StdEncoding.EncodeToString(k) }
	return []keyEnc{
		{"std", std},
		{"unpadded", func(k []byte) string { return base64.RawStdEncoding.EncodeToString(k) }},
		{"urlsafe", func(k []byte) string { return base64.URLEncoding.EncodeToString(k) }},
		{"split20", func(k []byte) string { s := std(k); return s[:20] + sep + s[20:] }},
		{"hex", func(k []byte) string { return hex.EncodeToString(k) }},
		{"hexsplit", func(k []byte) string { s := hex.EncodeToString(k); return s[:32] + sep + s[32:] }},
		{"colonhex", func(k []byte) string {
			parts := make([]string, len(k))
			for i, b := range k {
				parts[i] = hex.EncodeToString([]byte{b})
			}
			return strings.Join(parts, ":")
		}},
	}
}

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// buildConf renders a valid config, replacing the fields in over (address,
// dns, mtu, allowedips, endpoint) and appending extra raw lines.
func buildConf(nl, sep string, over map[string]string, extra func(kv func(k, v string) string) []string) string {
	kv := func(k, v string) string { return k + sep + "=" + sep + v }
	f := map[string]string{"address": "10.0.0.2/32", "dns": "10.0.0.1", "mtu": "1380", "allowedips": "10.0.0.0/24", "endpoint": "203.0.113.5:51820"}
	for k, v := range over {
		f[k] = v
	}
	lines := []string{
		"[Interface]", kv("PrivateKey", b64(1)), kv("Address", f["address"]), kv("DNS", f["dns"]), kv("MTU", f["mtu"]),
		"", "[Peer]", kv("PublicKey", b64(2)), kv("AllowedIPs", f["allowedips"]), kv("Endpoint", f["endpoint"]),
	}
	if extra != nil {
		lines = append(lines, extra(kv)...)
	}
	return strings.Join(lines, nl) + nl
}

// assertNoKeyRun fails if errText holds a run of 16 or more consecutive
// characters of encoded (case-insensitive, spaces and colons removed from both).
func assertNoKeyRun(t *testing.T, errText, encoded string) {
	t.Helper()
	norm := func(s string) string {
		return strings.NewReplacer(" ", "", ":", "", "\t", "").Replace(strings.ToLower(s))
	}
	e, k := norm(errText), norm(encoded)
	for i := 0; i+16 <= len(k); i++ {
		if strings.Contains(e, k[i:i+16]) {
			t.Fatalf("error leaks key material (%q): %q", k[i:i+16], errText)
		}
	}
}

func TestKeyLeakRegression(t *testing.T) {
	type place struct {
		name string
		cfg  func(nl, sep, v string) string
		// endpoint placements parse fine for some encodings; the leak check
		// then continues through ResolveEndpoints and WriteUAPI.
	}
	places := []place{
		{"Address", func(nl, sep, v string) string { return buildConf(nl, sep, map[string]string{"address": v}, nil) }},
		{"AllowedIPs", func(nl, sep, v string) string { return buildConf(nl, sep, map[string]string{"allowedips": v}, nil) }},
		{"Endpoint", func(nl, sep, v string) string {
			return buildConf(nl, sep, map[string]string{"endpoint": v + ":51820"}, nil)
		}},
		{"SectionHeader", func(nl, sep, v string) string {
			return buildConf(nl, sep, nil, func(kv func(k, v string) string) []string { return []string{"[" + v + "]"} })
		}},
		{"UnknownValue", func(nl, sep, v string) string {
			return buildConf(nl, sep, nil, func(kv func(k, v string) string) []string { return []string{kv("Bogus", v)} })
		}},
		{"UnknownName", func(nl, sep, v string) string {
			return buildConf(nl, sep, nil, func(kv func(k, v string) string) []string { return []string{kv(v, "1")} })
		}},
		{"DNS", func(nl, sep, v string) string {
			return buildConf(nl, sep, map[string]string{"dns": v}, func(kv func(k, v string) string) []string { return []string{kv("Bogus", "1")} })
		}},
		{"MTU", func(nl, sep, v string) string { return buildConf(nl, sep, map[string]string{"mtu": v}, nil) }},
	}
	cases := 0
	for round := 0; round < 3; round++ {
		key := randKey(t)
		for _, nl := range []string{"\n", "\r\n"} {
			for _, sep := range []string{" ", "\t"} {
				for _, enc := range keyEncodings(sep) {
					v := enc.val(key)
					for _, pl := range places {
						cases++
						text := pl.cfg(nl, sep, v)
						check := func(stage string, err error) {
							if err != nil {
								assertNoKeyRun(t, err.Error(), v)
							}
						}
						c, err := Parse(text)
						if err == nil && pl.name != "DNS" && pl.name != "Endpoint" {
							t.Fatalf("%s/%s: expected a parse error", pl.name, enc.name)
						}
						check("parse", err)
						if err != nil || c == nil {
							continue
						}
						fail := func(_ context.Context, host string) ([]netip.Addr, error) {
							return nil, errors.New("lookup " + strings.ToLower(host) + ": no such host")
						}
						check("resolve", ResolveEndpoints(context.Background(), c, fail))
						_, uerr := c.UAPI()
						check("uapi", uerr)
					}
				}
			}
		}
	}
	t.Logf("%d leak-regression cases", cases)
}

func TestParseZeroesKeysOnError(t *testing.T) {
	// Parse failing after PrivateKey was read must not hand back a config,
	// and must zero what it parsed (checked indirectly: no config returned).
	c, err := Parse(goodConf() + "Bogus = 1\n")
	if err == nil || c != nil {
		t.Fatalf("got %v, %v", c, err)
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

func TestStatsJSONDeviceErrorAndMaxLen(t *testing.T) {
	j := (Stats{LastDeviceError: "dev \"x\" é"}).JSON()
	if j != `{"last_handshake_unix_ms":0,"rx_bytes":0,"tx_bytes":0,"last_device_error":"dev 'x' ??"}` {
		t.Fatalf("got %s", j)
	}
	worst := Stats{
		LastHandshake:    time.UnixMilli(9999999999999),
		RxBytes:          ^uint64(0),
		TxBytes:          ^uint64(0),
		LastForwardError: strings.Repeat("e", 500),
		LastDeviceError:  strings.Repeat("d", 500),
	}.JSON()
	if len(worst) > MaxJSONLen {
		t.Fatalf("worst-case JSON is %d bytes, MaxJSONLen is %d", len(worst), MaxJSONLen)
	}
	if !strings.Contains(worst, strings.Repeat("d", 256)+`"`) || strings.Contains(worst, strings.Repeat("d", 257)) {
		t.Fatalf("device error not capped at 256: %s", worst)
	}
}
