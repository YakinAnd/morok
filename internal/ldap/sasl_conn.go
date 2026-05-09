package ldap

// saslConn wraps a net.Conn and provides GSSAPI SASL message wrapping/unwrapping.
// After a GSSAPI SASL bind, Windows AD encrypts all LDAP PDUs using the Kerberos
// session key. This conn transparently wraps outgoing PDUs with GSS_Wrap and
// unwraps/decrypts incoming ones.
//
// Wire format (RFC 4752 §3.3):
//
//	[4-byte big-endian length][GSS wrapped payload]
//
// Activation race (solved):
//
// go-ldap's reader goroutine blocks inside c.Conn.Read() before Activate() is
// called. We use short read deadlines (5 ms) to poll for activation, AND we
// read into a temporary buffer and re-check active AFTER Read() returns — this
// handles fast networks (VMware host-only < 1 ms) where data can arrive before
// the deadline fires. If active=true after the read, we stash the bytes into
// rawBuf and process them as a SASL frame.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Confidentiality flag in GSS WrapToken flags byte (RFC 4121 §4.2.2)
const wrapFlagSealed = 0x02

// saslConn wraps a net.Conn and applies GSSAPI SASL wrapping after Activate().
// Before Activate() is called it passes all traffic through unchanged.
type saslConn struct {
	net.Conn
	active     atomic.Bool
	sessionKey types.EncryptionKey
	seqNum     atomic.Uint64

	// Single-goroutine Read state (only go-ldap's reader goroutine calls Read).
	readBuf []byte // buffered plaintext from previous SASL unwrap (returned first)
	rawBuf  []byte // raw encrypted bytes captured during activation transition
}

func newSASLConn(inner net.Conn) *saslConn {
	return &saslConn{Conn: inner}
}

// Activate enables SASL wrapping with the given Kerberos session key.
func (c *saslConn) Activate(key types.EncryptionKey) {
	c.sessionKey = key
	c.active.Store(true)
}

// Write wraps the plaintext LDAP PDU in a GSSAPI WrapToken + 4-byte length header.
// The WrapToken is built manually so that SndSeqNum is set BEFORE SetCheckSum is
// called — gssapi.NewInitiatorWrapToken always uses SndSeqNum=0 for the checksum,
// which makes subsequent tokens (seqNum > 0) fail DC signature verification.
func (c *saslConn) Write(p []byte) (int, error) {
	if !c.active.Load() {
		return c.Conn.Write(p)
	}

	seqNum := c.seqNum.Add(1) - 1

	encType, err := crypto.GetEtype(c.sessionKey.KeyType)
	if err != nil {
		return 0, fmt.Errorf("sasl wrap: get etype: %w", err)
	}

	wt := gssapi.WrapToken{
		Flags:     0x00, // integrity-only (no sealing); initiator key
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: seqNum, // must be set BEFORE SetCheckSum
		Payload:   p,
	}
	if err := wt.SetCheckSum(c.sessionKey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return 0, fmt.Errorf("sasl wrap checksum: %w", err)
	}

	wrapped, err := wt.Marshal()
	if err != nil {
		return 0, fmt.Errorf("sasl wrap marshal: %w", err)
	}

	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(wrapped)))
	if _, err := c.Conn.Write(append(hdr, wrapped...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read implements io.Reader with transparent SASL unwrapping.
//
// Passthrough phase (active=false): reads raw bytes with a short deadline so
// we can detect activation. We read into a temporary buffer and re-check active
// AFTER the read returns — this handles the case where Activate() is called
// while c.Conn.Read() is already blocking (VMware/local networks are < 1ms so
// the deadline-based approach alone is not enough).
//
// SASL phase (active=true): reads one SASL-wrapped message, decrypts it, and
// returns the plaintext. Bytes pre-captured during the transition are processed
// first via rawBuf.
func (c *saslConn) Read(p []byte) (int, error) {
	// Return any buffered plaintext from a previous unwrap.
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Passthrough mode: read with short deadline so Activate() can be detected.
	for !c.active.Load() {
		tmp := make([]byte, len(p))
		c.Conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		n, err := c.Conn.Read(tmp)
		c.Conn.SetReadDeadline(time.Time{})
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // no data yet; loop and re-check active
			}
			return 0, err
		}
		// Data arrived. Re-check active: Activate() may have been called
		// while c.Conn.Read() was blocking.
		if !c.active.Load() {
			// Genuine passthrough data (bind exchange packets).
			return copy(p, tmp[:n]), nil
		}
		// Activate() was called while we were reading. The bytes in tmp[:n]
		// are the start of a SASL-encrypted frame. Stash them in rawBuf and
		// fall through to SASL mode below.
		c.rawBuf = append(c.rawBuf, tmp[:n]...)
		break
	}

	// SASL mode: read and unwrap one complete SASL frame.
	return c.readSASLFrame(p)
}

// readSASLFrame reads one complete [4-byte length][wrapped payload] frame from
// the wire (prepending any bytes already in rawBuf), decrypts it, and returns
// the plaintext.
func (c *saslConn) readSASLFrame(p []byte) (int, error) {
	// Ensure rawBuf has at least 4 bytes for the length header.
	for len(c.rawBuf) < 4 {
		tmp := make([]byte, 4096)
		n, err := c.Conn.Read(tmp)
		if err != nil {
			return 0, err
		}
		c.rawBuf = append(c.rawBuf, tmp[:n]...)
	}

	msgLen := int(binary.BigEndian.Uint32(c.rawBuf[:4]))
	if msgLen == 0 || msgLen > 16*1024*1024 {
		return 0, fmt.Errorf("sasl: invalid wrapped message length %d", msgLen)
	}

	total := 4 + msgLen

	// Ensure rawBuf has the complete frame.
	for len(c.rawBuf) < total {
		need := total - len(c.rawBuf)
		extra := make([]byte, need)
		if _, err := io.ReadFull(c.Conn, extra); err != nil {
			return 0, err
		}
		c.rawBuf = append(c.rawBuf, extra...)
	}

	// Unwrap the frame.
	wrapped := make([]byte, msgLen)
	copy(wrapped, c.rawBuf[4:total])
	c.rawBuf = c.rawBuf[total:] // consume the frame

	plaintext, err := c.unwrap(wrapped)
	if err != nil {
		return 0, fmt.Errorf("sasl unwrap: %w", err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.readBuf = append(c.readBuf, plaintext[n:]...)
	}
	return n, nil
}

// unwrap decodes a raw GSS WrapToken from the server (RFC 4121 §4.2.6).
// Handles both integrity-only and encrypted (Sealed) tokens.
func (c *saslConn) unwrap(b []byte) ([]byte, error) {
	if len(b) < 16 {
		return nil, fmt.Errorf("token too short (%d bytes)", len(b))
	}

	// Token ID: 0x05 0x04
	if b[0] != 0x05 || b[1] != 0x04 {
		return nil, fmt.Errorf("unexpected GSS WrapToken ID: %02x%02x", b[0], b[1])
	}

	flags := b[2]
	ec := binary.BigEndian.Uint16(b[4:6])  // extra count
	rrc := binary.BigEndian.Uint16(b[6:8]) // right rotation count

	body := make([]byte, len(b)-16)
	copy(body, b[16:])

	// Undo Right Rotation Count (RFC 4121 §4.2.5).
	if rrc > 0 && int(rrc) < len(body) {
		r := int(rrc)
		body = append(body[r:], body[:r]...)
	}

	if flags&wrapFlagSealed != 0 {
		// Encrypted: body = encrypt(plaintext || filler(EC bytes) || header-copy(16 bytes))
		plainConcat, err := crypto.DecryptMessage(body, c.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			return nil, fmt.Errorf("decrypt: %w", err)
		}
		trailerLen := int(ec) + 16
		if trailerLen > len(plainConcat) {
			return nil, fmt.Errorf("decrypted len %d < trailer %d", len(plainConcat), trailerLen)
		}
		return plainConcat[:len(plainConcat)-trailerLen], nil
	}

	// Integrity-only: body = plaintext || checksum(EC bytes)
	if int(ec) > len(body) {
		return nil, fmt.Errorf("integrity token: ec=%d > body=%d", ec, len(body))
	}
	return body[:len(body)-int(ec)], nil
}
