// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

package wgconf

import (
	"strconv"
	"strings"
	"time"
)

// Stats summarises tunnel counters across all peers.
type Stats struct {
	LastHandshake time.Time // zero if no handshake has completed
	RxBytes       uint64
	TxBytes       uint64
	// LastForwardError is the most recent forwarder error, if any. It is
	// ASCII-sanitised by JSON.
	LastForwardError string
	// LastDeviceError is the most recent error logged by wireguard-go, if
	// any. It is ASCII-sanitised by JSON.
	LastDeviceError string
}

// SanitizeASCII replaces every byte outside printable ASCII (0x20..0x7e)
// with '?' and truncates the result to max bytes (max <= 0 means no limit).
func SanitizeASCII(s string, max int) string {
	if max > 0 && len(s) > max {
		s = s[:max]
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}

// maxForwardErrJSON bounds last_forward_error in the JSON output.
const maxForwardErrJSON = 120

// maxDeviceErrJSON bounds last_device_error in the JSON output.
const maxDeviceErrJSON = 256

// MaxJSONLen is an upper bound on the length of Stats.JSON output; callers
// should provide a buffer of at least MaxJSONLen+1 bytes.
const MaxJSONLen = 560

func jsonString(s string, max int) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' {
			return '\''
		}
		return r
	}, SanitizeASCII(s, max))
}

// JSON renders the stats as a small JSON object. The output is printable
// ASCII only.
func (s Stats) JSON() string {
	var hs int64
	if !s.LastHandshake.IsZero() {
		hs = s.LastHandshake.UnixMilli()
	}
	out := `{"last_handshake_unix_ms":` + strconv.FormatInt(hs, 10) +
		`,"rx_bytes":` + strconv.FormatUint(s.RxBytes, 10) +
		`,"tx_bytes":` + strconv.FormatUint(s.TxBytes, 10)
	if s.LastForwardError != "" {
		out += `,"last_forward_error":"` + jsonString(s.LastForwardError, maxForwardErrJSON) + `"`
	}
	if s.LastDeviceError != "" {
		out += `,"last_device_error":"` + jsonString(s.LastDeviceError, maxDeviceErrJSON) + `"`
	}
	return out + `}`
}

// StatsWriter is an io.Writer that consumes the text produced by
// device.IpcGetOperation line by line and keeps only the handshake time and
// byte counters. The value part of any other line (in particular
// private_key and preshared_key) is skipped without being stored anywhere.
// The zero value is ready to use.
type StatsWriter struct {
	st          Stats
	hsSec, hsNs int64
	state       int // 0 = reading key, 1 = reading wanted value, 2 = skipping
	key         [32]byte
	keyN        int
	field       int
	val         [24]byte
	valN        int
	valOverflow bool
}

const (
	stKey = iota
	stVal
	stSkip
)

const (
	fNone = iota
	fSec
	fNsec
	fRx
	fTx
	fPub
)

func (w *StatsWriter) flushPeer() {
	if w.hsSec > 0 {
		t := time.Unix(w.hsSec, w.hsNs)
		if t.After(w.st.LastHandshake) {
			w.st.LastHandshake = t
		}
	}
	w.hsSec, w.hsNs = 0, 0
}

func (w *StatsWriter) endLine() {
	if w.state == stVal && !w.valOverflow {
		v := string(w.val[:w.valN])
		switch w.field {
		case fPub:
			w.flushPeer()
		case fSec:
			w.hsSec, _ = strconv.ParseInt(v, 10, 64)
		case fNsec:
			w.hsNs, _ = strconv.ParseInt(v, 10, 64)
		case fRx:
			n, _ := strconv.ParseUint(v, 10, 64)
			w.st.RxBytes += n
		case fTx:
			n, _ := strconv.ParseUint(v, 10, 64)
			w.st.TxBytes += n
		}
	}
	w.state, w.keyN, w.valN, w.field, w.valOverflow = stKey, 0, 0, fNone, false
}

func classify(k string) int {
	switch k {
	case "public_key":
		return fPub
	case "last_handshake_time_sec":
		return fSec
	case "last_handshake_time_nsec":
		return fNsec
	case "rx_bytes":
		return fRx
	case "tx_bytes":
		return fTx
	}
	return fNone
}

// Write implements io.Writer. It never fails.
func (w *StatsWriter) Write(p []byte) (int, error) {
	for _, c := range p {
		if c == '\n' {
			w.endLine()
			continue
		}
		switch w.state {
		case stKey:
			if c == '=' {
				w.field = classify(string(w.key[:w.keyN]))
				if w.field == fNone {
					w.state = stSkip
				} else {
					w.state = stVal
				}
			} else if w.keyN < len(w.key) {
				w.key[w.keyN] = c
				w.keyN++
			} else {
				w.state = stSkip // key too long: not one we want
			}
		case stVal:
			if c == '\r' || c == ' ' {
				continue
			}
			if w.valN < len(w.val) {
				w.val[w.valN] = c
				w.valN++
			} else {
				w.valOverflow = true
			}
		}
	}
	return len(p), nil
}

// Stats finishes any unterminated line and returns the totals. The
// handshake time is the most recent over all peers.
func (w *StatsWriter) Stats() Stats {
	w.endLine()
	w.flushPeer()
	return w.st
}

// ParseIpcStats extracts handshake time and byte counters from the text
// returned by device.IpcGet. Counters are summed over peers; the handshake
// time is the most recent one. Unknown or malformed lines are ignored.
func ParseIpcStats(s string) Stats {
	var w StatsWriter
	w.Write([]byte(s))
	return w.Stats()
}
