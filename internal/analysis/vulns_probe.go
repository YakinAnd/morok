package analysis

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const smbProbeTimeout = 5 * time.Second

// eternalBlueProbe detects MS17-010 via anonymous SMBv1 Trans2 SESSION_SETUP probe.
//
// Technique (same as nmap --script smb-vuln-ms17-010):
//  1. Anonymous null session to IPC$ over SMBv1
//  2. Send TRANS2_SESSION_SETUP (0x000E) with 4-byte parameter payload
//  3. Unpatched srv.sys hits the vulnerable FEA list size calculation and returns
//     STATUS_INSUFF_SERVER_RESOURCES (0xC0000205)
//  4. Patched systems return a different status code
// eternalBlueProbe returns (vulnerable, reachable):
//   - (true,  true)  — confirmed MS17-010 via Trans2 probe
//   - (false, true)  — host reachable but not vulnerable (patched or SMBv1 disabled)
//   - (false, false) — TCP connect failed; host unreachable on port 445
func eternalBlueProbe(host string) (vulnerable, reachable bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), smbProbeTimeout)
	if err != nil {
		return false, false // unreachable
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(smbProbeTimeout)) //nolint:errcheck

	if ok := smb1Negotiate(conn); !ok {
		return false, true // reachable but SMBv1 not accepted
	}
	uid, ok := smb1SessionSetupAnon(conn)
	if !ok {
		return false, true
	}
	tid, ok := smb1TreeConnect(conn, host, uid)
	if !ok {
		return false, true
	}
	return smb1Trans2Probe(conn, uid, tid), true
}

// ── NetBIOS framing ──────────────────────────────────────────────────────────

func smb1Send(conn net.Conn, payload []byte) error {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
	copy(frame[4:], payload)
	_, err := conn.Write(frame)
	return err
}

func smb1Recv(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(hdr[2:4]))
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// ── SMB header helpers ───────────────────────────────────────────────────────

func smb1MakeHeader(cmd byte, uid, tid uint16) []byte {
	h := make([]byte, 32)
	h[0] = 0xff; h[1] = 0x53; h[2] = 0x4d; h[3] = 0x42 // magic \xFFSMB
	h[4] = cmd
	h[9] = 0x18  // flags: case-insensitive, canonical paths
	h[10] = 0x53 // flags2 low: long names, EAs
	h[11] = 0xc8 // flags2 high: unicode, NT error codes
	binary.LittleEndian.PutUint16(h[24:], tid)
	h[26] = 0xff; h[27] = 0xfe // PID = 0xFEFF
	binary.LittleEndian.PutUint16(h[28:], uid)
	return h
}

func smb1IsMagic(resp []byte) bool {
	return len(resp) >= 4 &&
		resp[0] == 0xff && resp[1] == 0x53 && resp[2] == 0x4d && resp[3] == 0x42
}

func smb1Status(resp []byte) uint32 {
	if len(resp) < 9 {
		return 0xFFFFFFFF
	}
	return binary.LittleEndian.Uint32(resp[5:9])
}

func smb1UID(resp []byte) uint16 {
	if len(resp) < 30 {
		return 0
	}
	return binary.LittleEndian.Uint16(resp[28:30])
}

func smb1TID(resp []byte) uint16 {
	if len(resp) < 26 {
		return 0
	}
	return binary.LittleEndian.Uint16(resp[24:26])
}

// ── Step 1: Negotiate ────────────────────────────────────────────────────────

func smb1Negotiate(conn net.Conn) bool {
	dialect := append([]byte{0x02}, []byte("NT LM 0.12\x00")...)
	bc := uint16(len(dialect))

	pkt := smb1MakeHeader(0x72, 0, 0)
	pkt = append(pkt, 0x00)                  // WordCount = 0
	pkt = append(pkt, byte(bc), byte(bc>>8)) // ByteCount
	pkt = append(pkt, dialect...)

	if err := smb1Send(conn, pkt); err != nil {
		return false
	}
	resp, err := smb1Recv(conn)
	if err != nil || !smb1IsMagic(resp) {
		return false
	}
	// Status must be 0 (success); non-zero means SMBv1 refused
	return smb1Status(resp) == 0
}

// ── Step 2: Anonymous session setup ─────────────────────────────────────────

func smb1SessionSetupAnon(conn net.Conn) (uint16, bool) {
	// Null session: zero-length passwords, empty credential strings
	byteData := []byte{0x00, 0x00, 0x00, 0x00} // account\0 domain\0 NativeOS\0 NativeLM\0
	bc := uint16(len(byteData))

	pkt := smb1MakeHeader(0x73, 0, 0) // COM_SESSION_SETUP_ANDX
	pkt = append(pkt,
		0x0d,                   // WordCount = 13
		0xff, 0x00,             // AndXCommand=none, Reserved
		0x00, 0x00,             // AndXOffset
		0xff, 0xff,             // MaxBufferSize = 65535
		0x02, 0x00,             // MaxMpxCount = 2
		0x00, 0x00,             // VcNumber = 0
		0x00, 0x00, 0x00, 0x00, // SessionKey = 0
		0x00, 0x00,             // AnsiPasswordLength = 0
		0x00, 0x00,             // UnicodePasswordLength = 0
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities = 0
		byte(bc), byte(bc>>8),  // ByteCount
	)
	pkt = append(pkt, byteData...)

	if err := smb1Send(conn, pkt); err != nil {
		return 0, false
	}
	resp, err := smb1Recv(conn)
	if err != nil || !smb1IsMagic(resp) {
		return 0, false
	}
	st := smb1Status(resp)
	// 0 = success; 0xC0000016 = STATUS_MORE_PROCESSING_REQUIRED (NTLM challenge) — also ok for anon
	if st != 0 && st != 0xC0000016 {
		return 0, false
	}
	return smb1UID(resp), true
}

// ── Step 3: Tree connect to IPC$ ────────────────────────────────────────────

func smb1TreeConnect(conn net.Conn, host string, uid uint16) (uint16, bool) {
	path := "\\\\" + host + "\\IPC$\x00"
	service := "IPC\x00"
	byteData := []byte{0x00}            // 1-byte null password
	byteData = append(byteData, path...)
	byteData = append(byteData, service...)
	bc := uint16(len(byteData))

	pkt := smb1MakeHeader(0x75, uid, 0) // COM_TREE_CONNECT_ANDX
	pkt = append(pkt,
		0x04,                  // WordCount = 4
		0xff, 0x00,            // AndXCommand=none, Reserved
		0x00, 0x00,            // AndXOffset
		0x00, 0x00,            // Flags = 0
		0x01, 0x00,            // PasswordLength = 1 (the null byte)
		byte(bc), byte(bc>>8), // ByteCount
	)
	pkt = append(pkt, byteData...)

	if err := smb1Send(conn, pkt); err != nil {
		return 0, false
	}
	resp, err := smb1Recv(conn)
	if err != nil || !smb1IsMagic(resp) || smb1Status(resp) != 0 {
		return 0, false
	}
	return smb1TID(resp), true
}

// ── Step 4: Trans2 SESSION_SETUP probe ──────────────────────────────────────

// ── Step 4b: Open named pipe ─────────────────────────────────────────────────

// smb1OpenNamedPipe opens a named pipe using NT_CREATE_ANDX (0xa2).
// Returns (fid, exists, reachable):
//   - (fid, true,  true)  — pipe opened
//   - (0,   false, true)  — pipe not found (STATUS_OBJECT_NAME_NOT_FOUND)
//   - (0,   false, false) — transport/SMB error
func smb1OpenNamedPipe(conn net.Conn, uid, tid uint16, pipeName string) (fid uint16, exists bool, reachable bool) {
	// pipeName should be like "\spoolss" or "\lsarpc" (relative to IPC$ root)
	nameW := utf16LEZ(pipeName)
	bc := uint16(len(nameW) + 1) // +1 for the 0x00 pad/align byte

	pkt := smb1MakeHeader(0xa2, uid, tid) // COM_NT_CREATE_ANDX
	pkt = append(pkt,
		0x18,                            // WordCount = 24
		0xff, 0x00,                      // AndXCommand=none, Reserved
		0x00, 0x00,                      // AndXOffset
		0x00,                            // Reserved
		byte(len(nameW)), 0x00,          // NameLength
		0x16, 0x00, 0x00, 0x00,          // Flags = 0x16 (request oplocks)
		0x00, 0x00, 0x00, 0x00,          // RootDirectoryFid = 0
		0x02, 0x00, 0x12, 0x00,          // DesiredAccess = 0x00120002 (READ_DATA | READ_ATTRIBUTES | SYNCHRONIZE)
		0x00, 0x00, 0x00, 0x00,          // AllocationSize low
		0x00, 0x00, 0x00, 0x00,          // AllocationSize high
		0x00, 0x00, 0x00, 0x00,          // FileAttributes = 0 (normal)
		0x07, 0x00, 0x00, 0x00,          // ShareAccess = FILE_SHARE_READ|WRITE|DELETE
		0x01, 0x00, 0x00, 0x00,          // CreateDisposition = FILE_OPEN
		0x00, 0x00, 0x00, 0x00,          // CreateOptions = 0
		0xff, 0xff, 0xff, 0xff,          // ImpersonationLevel = SecurityImpersonation
		0x00,                            // SecurityFlags
		byte(bc), byte(bc>>8),           // ByteCount
		0x00,                            // pad byte
	)
	pkt = append(pkt, nameW...)

	if err := smb1Send(conn, pkt); err != nil {
		return 0, false, false
	}
	resp, err := smb1Recv(conn)
	if err != nil || !smb1IsMagic(resp) {
		return 0, false, false
	}
	st := smb1Status(resp)
	if st == 0xC0000034 || st == 0xC000003A { // OBJECT_NAME_NOT_FOUND or PATH_NOT_FOUND
		return 0, false, true
	}
	if st != 0 && st != 0xC0000022 { // not SUCCESS or ACCESS_DENIED
		return 0, false, true
	}
	// FID is at word offset 5 of the parameter words, after the 32-byte header + 1 WordCount byte.
	// NT_CREATE_ANDX response: header(32) + WordCount(1) + AndXCommand(1) + Reserved(1) + AndXOffset(2) + OplockLevel(1) + Fid(2)
	if len(resp) < 42 {
		return 0, false, true
	}
	fid = binary.LittleEndian.Uint16(resp[38:40])
	return fid, true, true
}

// utf16LEZ encodes a UTF-8 string as little-endian UTF-16 with null terminator.
func utf16LEZ(s string) []byte {
	out := make([]byte, (len(s)+1)*2)
	for i, r := range s {
		out[i*2] = byte(r)
		out[i*2+1] = 0x00
	}
	return out
}

// ── Step 4c: Write to pipe ───────────────────────────────────────────────────

func smb1WritePipe(conn net.Conn, uid, tid, fid uint16, data []byte) error {
	dl := uint16(len(data))
	const dataOff = 63 // header(32)+WordCount(1)+14words*2+ByteCount(2) = 63

	pkt := smb1MakeHeader(0x2f, uid, tid) // COM_WRITE_ANDX
	pkt = append(pkt,
		0x0e,                  // WordCount = 14
		0xff, 0x00,            // AndXCommand=none, Reserved
		0x00, 0x00,            // AndXOffset
		byte(fid), byte(fid>>8),
		0x00, 0x00, 0x00, 0x00, // Offset = 0
		0xff, 0xff, 0xff, 0xff, // Timeout = -1 (wait forever)
		0x08, 0x00,             // WriteMode = 0x0008 (start of message)
		0x00, 0x00,             // Remaining = 0
		0x00, 0x00,             // DataLengthHigh = 0
		byte(dl), byte(dl>>8), // DataLength
		dataOff, 0x00,          // DataOffset
		0x00, 0x00, 0x00, 0x00, // HighOffset = 0
		byte(dl + 1), byte((dl+1)>>8), // ByteCount (1 pad + data)
		0x00,                   // pad byte
	)
	pkt = append(pkt, data...)

	if err := smb1Send(conn, pkt); err != nil {
		return err
	}
	resp, err := smb1Recv(conn)
	if err != nil || !smb1IsMagic(resp) {
		return err
	}
	if smb1Status(resp) != 0 {
		return fmt.Errorf("WRITE_ANDX status 0x%08X", smb1Status(resp))
	}
	return nil
}

// ── Step 4d: Read pipe response ──────────────────────────────────────────────

func smb1ReadPipeData(conn net.Conn, uid, tid, fid uint16) ([]byte, error) {
	pkt := smb1MakeHeader(0x2e, uid, tid) // COM_READ_ANDX
	pkt = append(pkt,
		0x0c,                   // WordCount = 12
		0xff, 0x00,             // AndXCommand=none, Reserved
		0x00, 0x00,             // AndXOffset
		byte(fid), byte(fid>>8),
		0x00, 0x00, 0x00, 0x00, // Offset = 0
		0xff, 0x05,             // MaxCountLow = 0x05FF (1535)
		0x00, 0x00,             // MinCount = 0
		0xff, 0xff, 0xff, 0xff, // Timeout = -1
		0x00, 0x00,             // Remaining = 0
		0x00, 0x00, 0x00, 0x00, // OffsetHigh = 0
		0x00, 0x00,             // ByteCount = 0
	)

	if err := smb1Send(conn, pkt); err != nil {
		return nil, err
	}
	resp, err := smb1Recv(conn)
	if err != nil || !smb1IsMagic(resp) {
		return nil, err
	}
	st := smb1Status(resp)
	if st != 0 {
		return nil, fmt.Errorf("READ_ANDX status 0x%08X", st)
	}
	// DataLength at resp[43:45], DataOffset at resp[45:47]
	if len(resp) < 47 {
		return nil, fmt.Errorf("READ_ANDX response too short")
	}
	dataLen := int(binary.LittleEndian.Uint16(resp[43:45]))
	dataOff := int(binary.LittleEndian.Uint16(resp[45:47]))
	if dataOff+dataLen > len(resp) {
		return nil, fmt.Errorf("READ_ANDX data out of bounds")
	}
	return resp[dataOff : dataOff+dataLen], nil
}

// ── DCE/RPC over SMB named pipe ──────────────────────────────────────────────

// netlogonRPCBind returns the fixed 72-byte DCE/RPC bind packet for the
// Netlogon interface UUID 12345678-1234-abcd-ef00-01234567cffb v1.0.
func netlogonRPCBind() []byte {
	return []byte{
		// DCE/RPC header (16 bytes)
		0x05, 0x00, // version 5.0
		0x0b, 0x03, // BIND, PFC_FIRST_FRAG|PFC_LAST_FRAG
		0x10, 0x00, 0x00, 0x00, // data representation: LE, ASCII, IEEE float
		0x48, 0x00, // frag length = 72
		0x00, 0x00, // auth length = 0
		0x41, 0x00, 0x00, 0x00, // call ID = 0x41
		// Bind body
		0xd0, 0x16,              // max_xmit_frag = 5840
		0xd0, 0x16,              // max_recv_frag = 5840
		0x00, 0x00, 0x00, 0x00, // assoc_group = 0
		0x01, 0x00, 0x00, 0x00, // num_ctx_items = 1
		// p_context_elem[0]
		0x00, 0x00,             // context_id = 0
		0x01, 0x00,             // num_transfer_syntaxes = 1
		// abstract syntax: Netlogon 12345678-1234-abcd-ef00-01234567cffb v1.0
		0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
		0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb,
		0x01, 0x00, 0x00, 0x00, // if_version = 1
		// transfer syntax: NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		0x02, 0x00, 0x00, 0x00, // syntax_version = 2
	}
}

// netlogonAuthenticate2NDR builds an NDR-encoded NetrServerAuthenticate2
// request (opnum 15) with all-zero ClientCredential and NegotiateFlags=0.
// A vulnerable DC returns STATUS_SUCCESS (0x00000000) because it accepts
// zero credentials due to the Zerologon AES-CFB8 all-zero IV collision.
func netlogonAuthenticate2NDR(dcAccount string) []byte {
	// NDR: PrimaryName (NULL pointer), AccountName, SecureChannelType (BDC=6),
	//      ComputerName, ClientCredential (8 zeros), NegotiateFlags pointer (0)
	account := dcAccount
	if len(account) > 0 && account[len(account)-1] != '$' {
		account += "$"
	}

	encStr := func(s string) []byte {
		// NDR conformant string: MaxCount(4) + Offset(4) + ActualCount(4) + chars + align
		b := make([]byte, 12)
		binary.LittleEndian.PutUint32(b[0:4], uint32(len(s)+1))
		binary.LittleEndian.PutUint32(b[4:8], 0)
		binary.LittleEndian.PutUint32(b[8:12], uint32(len(s)+1))
		for _, c := range s {
			b = append(b, byte(c))
		}
		b = append(b, 0x00) // null term
		// 4-byte align
		for len(b)%4 != 0 {
			b = append(b, 0x00)
		}
		return b
	}

	var body []byte
	body = append(body,
		0x00, 0x00, 0x00, 0x00, // PrimaryName = NULL pointer
	)
	body = append(body,
		0x01, 0x00, 0x00, 0x00, // AccountName referent
	)
	body = append(body, encStr(account)...)
	body = append(body,
		0x06, 0x00, // SecureChannelType = BDC (6)
		0x00, 0x00, // pad
	)
	body = append(body,
		0x02, 0x00, 0x00, 0x00, // ComputerName referent
	)
	body = append(body, encStr(account)...)
	body = append(body,
		// ClientCredential: 8 zero bytes (the Zerologon trick)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// NegotiateFlags: 0
		0x00, 0x00, 0x00, 0x00,
	)

	totalLen := 16 + 4 + len(body) // DCE header(16) + opnum padding(4) + body
	hdr := []byte{
		0x05, 0x00, // version 5.0
		0x00, 0x03, // REQUEST, PFC_FIRST_FRAG|PFC_LAST_FRAG
		0x10, 0x00, 0x00, 0x00, // data representation
		byte(totalLen), byte(totalLen >> 8), // frag length
		0x00, 0x00, // auth length = 0
		0x42, 0x00, 0x00, 0x00, // call ID = 0x42
		byte(len(body)), byte(len(body) >> 8), 0x00, 0x00, // alloc_hint
		0x00, 0x00, // context_id = 0
		0x0f, 0x00, // opnum = 15 (NetrServerAuthenticate2)
	}
	return append(hdr, body...)
}

// zerologonProbe attempts Zerologon (CVE-2020-1472) by sending
// NetrServerAuthenticate2 with zero credentials over the Netlogon RPC pipe.
// Returns (vulnerable, reachable).
func zerologonProbe(host, dcAccount string) (vulnerable, reachable bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), smbProbeTimeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(smbProbeTimeout)) //nolint:errcheck

	if ok := smb1Negotiate(conn); !ok {
		return false, true
	}
	uid, ok := smb1SessionSetupAnon(conn)
	if !ok {
		return false, true
	}
	tid, ok := smb1TreeConnect(conn, host, uid)
	if !ok {
		return false, true
	}
	fid, exists, reachable2 := smb1OpenNamedPipe(conn, uid, tid, "\\netlogon")
	if !reachable2 {
		return false, true
	}
	if !exists {
		return false, true // pipe not present — can't probe
	}

	if err := smb1WritePipe(conn, uid, tid, fid, netlogonRPCBind()); err != nil {
		return false, true
	}
	bindResp, err := smb1ReadPipeData(conn, uid, tid, fid)
	if err != nil || len(bindResp) < 20 {
		return false, true
	}
	// Check bind ack (packet type 0x0c = BIND_ACK)
	if bindResp[2] != 0x0c {
		return false, true
	}

	req := netlogonAuthenticate2NDR(dcAccount)
	if err := smb1WritePipe(conn, uid, tid, fid, req); err != nil {
		return false, true
	}
	authResp, err := smb1ReadPipeData(conn, uid, tid, fid)
	if err != nil || len(authResp) < 24 {
		return false, true
	}
	// DCE/RPC response: return code is last 4 bytes
	retCode := binary.LittleEndian.Uint32(authResp[len(authResp)-4:])
	// STATUS_SUCCESS (0x00000000) = DC accepted zero credential → vulnerable
	// STATUS_ACCESS_DENIED (0xC0000022) or 0xC000006D etc. = patched
	return retCode == 0, true
}

// printNightmareProbe checks if the Print Spooler named pipe is accessible,
// confirming the service is running (prerequisite for PrintNightmare).
// Returns (spoolerRunning, reachable).
func printNightmareProbe(host string) (spoolerRunning, reachable bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), smbProbeTimeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(smbProbeTimeout)) //nolint:errcheck

	if ok := smb1Negotiate(conn); !ok {
		return false, true
	}
	uid, ok := smb1SessionSetupAnon(conn)
	if !ok {
		return false, true
	}
	tid, ok := smb1TreeConnect(conn, host, uid)
	if !ok {
		return false, true
	}
	_, exists, reachable2 := smb1OpenNamedPipe(conn, uid, tid, "\\spoolss")
	if !reachable2 {
		return false, true
	}
	// exists=true: pipe present → Spooler running → vulnerable
	// exists=false: pipe absent → Spooler disabled → safe
	return exists, true
}

// ── Step 4: Trans2 SESSION_SETUP probe ──────────────────────────────────────

// smb1Trans2Probe sends TRANS2_SESSION_SETUP (0x000E) with 4-byte parameter data.
//
// Packet layout (offsets from start of SMB header):
//   0-31  SMB header (32 bytes)
//   32    WordCount = 15
//   33-62 Transaction2 words (30 bytes)
//   63-64 ByteCount = 7
//   65-67 3 pad bytes
//   68-71 4 bytes parameter data (zeros) ← ParameterOffset = 0x44
//
// STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) in the response = vulnerable.
func smb1Trans2Probe(conn net.Conn, uid, tid uint16) bool {
	const (
		paramOff = 0x44 // 32+1+30+2+3 = 68
		dataOff  = 0x48 // paramOff + 4 (param data length)
	)

	pkt := smb1MakeHeader(0x32, uid, tid) // SMB_COM_TRANSACTION2
	pkt = append(pkt,
		0x0f,                            // WordCount = 15
		0x04, 0x00,                      // TotalParameterCount = 4
		0x00, 0x00,                      // TotalDataCount = 0
		0x00, 0x00,                      // MaxParameterCount = 0
		0x00, 0x00,                      // MaxDataCount = 0
		0x00, 0x00,                      // MaxSetupCount=0, Reserved
		0x00, 0x00,                      // Flags = 0
		0x00, 0x00, 0x00, 0x00,          // Timeout = 0
		0x00, 0x00,                      // Reserved2
		0x04, 0x00,                      // ParameterCount = 4
		paramOff, 0x00,                  // ParameterOffset
		0x00, 0x00,                      // DataCount = 0
		dataOff, 0x00,                   // DataOffset
		0x01, 0x00,                      // SetupCount=1, Reserved
		0x0e, 0x00,                      // Setup[0] = TRANS2_SESSION_SETUP
		0x07, 0x00,                      // ByteCount = 7 (3 pad + 4 param data)
		0x00, 0x00, 0x00,                // 3 pad bytes (align to word boundary)
		0x00, 0x00, 0x00, 0x00,          // 4 bytes parameter data (zeros)
	)

	if err := smb1Send(conn, pkt); err != nil {
		return false
	}
	resp, err := smb1Recv(conn)
	if err != nil || !smb1IsMagic(resp) {
		return false
	}
	return smb1Status(resp) == 0xC0000205
}
