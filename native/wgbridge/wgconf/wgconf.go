// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

// Package wgconf parses wg-quick style WireGuard configuration text and
// converts it to the cross-platform "UAPI" text accepted by
// device.IpcSet in wireguard-go. It only uses the standard library.
//
// Key material is never included in error messages: user-supplied values
// that are echoed go through safeQuote, and unknown keys through unknownKey.
package wgconf

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// maxConfigSize bounds the accepted configuration text.
const maxConfigSize = 1 << 20

// KeyLen is the length in bytes of WireGuard keys.
const KeyLen = 32

// Key is a raw 32-byte WireGuard key.
type Key [KeyLen]byte

// IsZero reports whether k is all zero bytes.
func (k Key) IsZero() bool { return k == Key{} }

// Config is a parsed WireGuard configuration.
type Config struct {
	PrivateKey Key
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int // 0 means "use the default"
	ListenPort int // 0 means "random"
	Peers      []Peer
}

// Peer is one [Peer] section.
type Peer struct {
	PublicKey    Key
	PresharedKey Key
	HasPSK       bool
	AllowedIPs   []netip.Prefix

	// EndpointHost and EndpointPort are the endpoint as written in the file
	// (EndpointHost without brackets). Empty EndpointHost means no endpoint.
	EndpointHost string
	EndpointPort uint16
	// ResolvedEndpoint is the ip:port used for UAPI. It is set at parse time
	// for IP literals and by ResolveEndpoints for host names.
	ResolvedEndpoint netip.AddrPort

	PersistentKeepalive int // seconds, 0 = off
}

// LookupFunc resolves a host name to IP addresses.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ResolveEndpoints resolves every peer endpoint host name to an IP address
// (IPv4 preferred) so that UAPI can be generated. IP literals are left
// alone. A nil lookup uses the system resolver.
func ResolveEndpoints(ctx context.Context, c *Config, lookup LookupFunc) error {
	if lookup == nil {
		lookup = defaultLookup
	}
	for i := range c.Peers {
		p := &c.Peers[i]
		if p.EndpointHost == "" || p.ResolvedEndpoint.IsValid() {
			continue
		}
		addrs, err := lookup(ctx, p.EndpointHost)
		if err != nil {
			// Never echo the resolver's text: it may repeat the host name
			// in a transformed (for example lower-cased) form.
			reason := "lookup failed"
			var de *net.DNSError
			switch {
			case errors.As(err, &de) && de.IsNotFound:
				reason = "no such host"
			case errors.As(err, &de) && de.IsTimeout, errors.Is(err, context.DeadlineExceeded):
				reason = "timeout"
			case errors.As(err, &de) && de.IsTemporary:
				reason = "temporary DNS failure"
			}
			return fmt.Errorf("wgconf: resolve endpoint of peer %d (%s): %s", i+1, safeQuote(p.EndpointHost), reason)
		}
		var chosen netip.Addr
		for _, a := range addrs {
			a = a.Unmap()
			if !a.IsValid() {
				continue
			}
			if a.Is4() {
				chosen = a
				break
			}
			if !chosen.IsValid() {
				chosen = a
			}
		}
		if !chosen.IsValid() {
			return fmt.Errorf("wgconf: endpoint host %s of peer %d has no addresses", safeQuote(p.EndpointHost), i+1)
		}
		p.ResolvedEndpoint = netip.AddrPortFrom(chosen, p.EndpointPort)
	}
	return nil
}

// safeQuote quotes a user value for an error message. It is echoed only if it
// holds fewer than 16 characters from the base64/base64url/hex alphabets in
// total (separators are not counted, so split, wrapped, colon-hex and
// URL-safe keys are caught).
func safeQuote(s string) string {
	s = strings.TrimSpace(s)
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '+' || c == '/' || c == '-' || c == '_' {
			n++
		}
	}
	if n >= 16 {
		return "<redacted key-like value>"
	}
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	return strconv.QuoteToASCII(s)
}

// unknownKey builds the error for an unrecognised option name. Anything that
// does not look like a plain option name (for example a key pasted where an
// option name belongs, split at its '=' padding) is not echoed.
func unknownKey(section, key string) error {
	if len(key) > 32 {
		return fmt.Errorf("malformed line in %s (expected Key = Value)", section)
	}
	for _, r := range key {
		if r < 'a' || r > 'z' {
			return fmt.Errorf("malformed line in %s (expected Key = Value)", section)
		}
	}
	return fmt.Errorf("unknown %s key %q", section, key)
}

func parseKey(field, v string) (Key, error) {
	var k Key
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return k, fmt.Errorf("%s is not valid base64", field)
	}
	defer clear(raw)
	if len(raw) != KeyLen {
		return k, fmt.Errorf("%s must decode to %d bytes (got %d)", field, KeyLen, len(raw))
	}
	copy(k[:], raw)
	return k, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parseInt(field, v string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%s is not a number", field)
	}
	if n < lo || n > hi {
		return 0, fmt.Errorf("%s out of range [%d, %d]", field, lo, hi)
	}
	return n, nil
}

func parseEndpoint(v string) (host string, port uint16, lit netip.AddrPort, err error) {
	h, ps, err := net.SplitHostPort(strings.TrimSpace(v))
	if err != nil {
		return "", 0, netip.AddrPort{}, errors.New("Endpoint must be host:port or [ipv6]:port")
	}
	if h == "" {
		return "", 0, netip.AddrPort{}, errors.New("Endpoint host is empty")
	}
	pn, err := strconv.Atoi(ps)
	if err != nil || pn < 1 || pn > 65535 {
		return "", 0, netip.AddrPort{}, errors.New("Endpoint port must be 1-65535")
	}
	if a, perr := netip.ParseAddr(h); perr == nil {
		a = a.Unmap()
		lit = netip.AddrPortFrom(a, uint16(pn))
	}
	return h, uint16(pn), lit, nil
}

// Parse parses wg-quick style configuration text. wg-quick script hooks
// (PreUp, PostUp, ...) are rejected rather than ignored.
//
// Parse must not retain substrings of text: the caller may pass a string that
// aliases memory it zeroes afterwards (see cmd/libwgbridge). Every string
// stored in the returned Config is therefore a copy (strings.Clone). On error
// any key material already parsed is zeroed.
func Parse(text string) (_ *Config, err error) {
	if len(text) > maxConfigSize {
		return nil, errors.New("wgconf: config too large")
	}
	text = strings.TrimPrefix(text, "\xef\xbb\xbf")
	c := &Config{}
	defer func() {
		if err != nil {
			c.Zero()
		}
	}()
	section := ""
	sawInterface := false
	var cur *Peer

	for n, line := range strings.Split(text, "\n") {
		ln := n + 1
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				if sawInterface {
					return nil, fmt.Errorf("wgconf: line %d: duplicate [Interface] section", ln)
				}
				sawInterface = true
				section = "interface"
			case "[peer]":
				c.Peers = append(c.Peers, Peer{})
				cur = &c.Peers[len(c.Peers)-1]
				section = "peer"
			default:
				return nil, fmt.Errorf("wgconf: line %d: unknown section %s", ln, safeQuote(line))
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("wgconf: line %d: expected key = value", ln)
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		wrap := func(err error) error { return fmt.Errorf("wgconf: line %d: %w", ln, err) }

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				k, err := parseKey("PrivateKey", val)
				if err != nil {
					return nil, wrap(err)
				}
				c.PrivateKey = k
			case "address":
				for _, s := range splitList(val) {
					p, err := parsePrefix(s)
					if err != nil {
						return nil, wrap(fmt.Errorf("invalid Address %s", safeQuote(s)))
					}
					c.Addresses = append(c.Addresses, p)
				}
			case "dns":
				for _, s := range splitList(val) {
					if a, err := netip.ParseAddr(s); err == nil {
						c.DNS = append(c.DNS, a.Unmap())
					} // non-IP entries are DNS search domains: ignored
				}
			case "mtu":
				m, err := parseInt("MTU", val, 576, 9216)
				if err != nil {
					return nil, wrap(err)
				}
				c.MTU = m
			case "listenport":
				p, err := parseInt("ListenPort", val, 0, 65535)
				if err != nil {
					return nil, wrap(err)
				}
				c.ListenPort = p
			case "table", "saveconfig", "fwmark":
				// meaningless for an in-process tunnel
			case "preup", "postup", "predown", "postdown":
				return nil, wrap(errors.New("script hooks (PreUp/PostUp/PreDown/PostDown) are not supported"))
			default:
				return nil, wrap(unknownKey("[Interface]", key))
			}
		case "peer":
			switch key {
			case "publickey":
				k, err := parseKey("PublicKey", val)
				if err != nil {
					return nil, wrap(err)
				}
				cur.PublicKey = k
			case "presharedkey":
				k, err := parseKey("PresharedKey", val)
				if err != nil {
					return nil, wrap(err)
				}
				cur.PresharedKey, cur.HasPSK = k, true
			case "allowedips":
				for _, s := range splitList(val) {
					p, err := parsePrefix(s)
					if err != nil {
						return nil, wrap(fmt.Errorf("invalid AllowedIPs entry %s", safeQuote(s)))
					}
					cur.AllowedIPs = append(cur.AllowedIPs, p.Masked())
				}
			case "endpoint":
				h, p, lit, err := parseEndpoint(val)
				if err != nil {
					return nil, wrap(err)
				}
				cur.EndpointHost, cur.EndpointPort, cur.ResolvedEndpoint = strings.Clone(h), p, lit
			case "persistentkeepalive":
				if strings.EqualFold(val, "off") {
					cur.PersistentKeepalive = 0
					break
				}
				k, err := parseInt("PersistentKeepalive", val, 0, 65535)
				if err != nil {
					return nil, wrap(err)
				}
				cur.PersistentKeepalive = k
			default:
				return nil, wrap(unknownKey("[Peer]", key))
			}
		default:
			return nil, fmt.Errorf("wgconf: line %d: key outside any section", ln)
		}
	}

	if !sawInterface {
		return nil, errors.New("wgconf: missing [Interface] section")
	}
	if c.PrivateKey.IsZero() {
		return nil, errors.New("wgconf: [Interface] PrivateKey is required")
	}
	if len(c.Addresses) == 0 {
		return nil, errors.New("wgconf: [Interface] Address is required")
	}
	if len(c.Peers) == 0 {
		return nil, errors.New("wgconf: at least one [Peer] is required")
	}
	for i, p := range c.Peers {
		if p.PublicKey.IsZero() {
			return nil, fmt.Errorf("wgconf: peer %d: PublicKey is required", i+1)
		}
	}
	return c, nil
}

// WriteUAPI renders the configuration as text for device.IpcSetOperation
// into w. All endpoints that are set must already be resolved (see
// ResolveEndpoints); nothing is written if that check fails. Key bytes are
// hex-encoded through a stack buffer rather than intermediate strings, and w
// is grown up front so that it is never reallocated (which would leave an
// unzeroable copy of the keys behind). The caller should zero w's bytes when
// done.
func (c *Config) WriteUAPI(w *bytes.Buffer) error {
	size := 128
	for i, p := range c.Peers {
		if p.EndpointHost != "" && !p.ResolvedEndpoint.IsValid() {
			return fmt.Errorf("wgconf: peer %d endpoint %s is not resolved", i+1, safeQuote(p.EndpointHost))
		}
		size += 384 + 64*len(p.AllowedIPs) + len(p.EndpointHost) + len(p.ResolvedEndpoint.String())
	}
	w.Grow(size)

	var hx [2 * KeyLen]byte
	writeKey := func(name string, k *Key) {
		hex.Encode(hx[:], k[:])
		w.WriteString(name)
		w.Write(hx[:])
		w.WriteByte('\n')
		clear(hx[:])
	}
	writeKey("private_key=", &c.PrivateKey)
	if c.ListenPort > 0 {
		w.WriteString("listen_port=" + strconv.Itoa(c.ListenPort) + "\n")
	}
	w.WriteString("replace_peers=true\n")
	for i := range c.Peers {
		p := &c.Peers[i]
		writeKey("public_key=", &p.PublicKey)
		if p.HasPSK {
			writeKey("preshared_key=", &p.PresharedKey)
		}
		if p.EndpointHost != "" {
			w.WriteString("endpoint=" + p.ResolvedEndpoint.String() + "\n")
		}
		if p.PersistentKeepalive > 0 {
			w.WriteString("persistent_keepalive_interval=" + strconv.Itoa(p.PersistentKeepalive) + "\n")
		}
		w.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.AllowedIPs {
			w.WriteString("allowed_ip=" + ip.String() + "\n")
		}
	}
	return nil
}

// UAPI renders the configuration as a string (see WriteUAPI). Prefer
// WriteUAPI when the result will carry key material in production code: a
// string cannot be zeroed.
func (c *Config) UAPI() (string, error) {
	var b bytes.Buffer
	if err := c.WriteUAPI(&b); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Zero overwrites the private key and every preshared key in c.
func (c *Config) Zero() {
	c.PrivateKey = Key{}
	for i := range c.Peers {
		c.Peers[i].PresharedKey = Key{}
	}
}
