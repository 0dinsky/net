// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"crypto/rand"
	"math/big"
)

// pickDataPaddingLen returns a random padding length (bytes) for a DATA
// frame carrying dataLen bytes of payload, sampled uniformly from
// [min, max] and clamped so the resulting frame:
//   - never exceeds maxFrameSize (the peer's negotiated SETTINGS_MAX_FRAME_SIZE)
//   - never asks for more than 255 bytes of padding, since the PADDED
//     flag's pad-length field (RFC 7540 §6.1) is a single byte
//
// Returns 0 (no padding) if padding is disabled (max<=0) or there's no
// room left in the frame for any padding at all.
func pickDataPaddingLen(min, max, dataLen, maxFrameSize int) int {
	if max <= 0 {
		return 0
	}
	if max > 255 {
		max = 255
	}
	if min < 0 {
		min = 0
	}
	if min > max {
		min = max
	}
	// The pad-length byte itself also counts against maxFrameSize.
	room := maxFrameSize - dataLen - 1
	if room <= 0 {
		return 0
	}
	if max > room {
		max = room
	}
	if min > max {
		min = max
	}
	if max == min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

// dataPadding returns padLen padding bytes for use with WriteDataPadded.
// Per RFC 7540 §6.1 ("Padding octets MUST be set to zero when sending"),
// and per this Framer's own AllowIllegalWrites check, these must be zero —
// which is exactly what a freshly-allocated slice already is, so there's
// nothing to fill in. Only the *length* needs to be unpredictable to hide
// real content size from a passive observer; the padding bytes' contents
// are never meaningful. Returns nil if padLen<=0 (WriteDataPadded then
// omits the PADDED flag entirely, same as a plain WriteData).
func dataPadding(padLen int) []byte {
	if padLen <= 0 {
		return nil
	}
	return make([]byte, padLen)
}
