package helpers

import "encoding/binary"

const halfsize = 4
const (
	tsIdx uint = iota << 3
	pidIdx
	sslpIdx
	sslcIdx
	payloadIdx
)
const tgidIdx = pidIdx + halfsize
const pLenIdx = payloadIdx - halfsize

type dataHeaders struct {
	Pid        uint32 // Process ID (Userspace Thread ID)
	Tgid       uint32 // Thread-group ID (Userspace PID)
	Sslp       uint64 // TLS connection ID
	Sslc       uint32 // TLS connection counter
	Ktime      uint64 // timestamp
	PayloadLen uint32 // length of payload
	Raw        *rawDataHeaders
}

type rawDataHeaders struct {
	PayloadLen []byte
	Pid        []byte
	Tgid       []byte
	Sslp       []byte
	Sslc       []byte
	Ts         []byte
}

func ParseDataHeaders(raw []byte) *dataHeaders {
	if len(raw) < 32 {
		return nil
	}

	rawHeaders := &rawDataHeaders{
		Ts:         raw[tsIdx:pidIdx],
		Pid:        raw[pidIdx:tgidIdx],
		Tgid:       raw[tgidIdx:sslpIdx],
		Sslp:       raw[sslpIdx:sslcIdx],
		Sslc:       raw[sslcIdx:pLenIdx],
		PayloadLen: raw[pLenIdx:payloadIdx],
	}

	headers := &dataHeaders{
		Raw: rawHeaders,
	}

	headers.Pid = binary.LittleEndian.Uint32(headers.Raw.Pid)
	headers.Tgid = binary.LittleEndian.Uint32(headers.Raw.Tgid)
	headers.Sslp = binary.LittleEndian.Uint64(headers.Raw.Sslp)
	headers.Sslc = binary.LittleEndian.Uint32(headers.Raw.Sslc)
	headers.Ktime = binary.LittleEndian.Uint64(headers.Raw.Ts)
	headers.PayloadLen = binary.LittleEndian.Uint32(headers.Raw.PayloadLen)

	return headers

}

func (dh *dataHeaders) GetId() [20]byte {
	var id [20]byte
	copy(id[:4], dh.Raw.Pid)
	copy(id[4:8], dh.Raw.Tgid)
	copy(id[8:16], dh.Raw.Sslp)
	copy(id[16:20], dh.Raw.Sslc)

	return id
}

func (dh *dataHeaders) GetPayload(raw []byte) []byte {
	return raw[payloadIdx : uint32(payloadIdx)+dh.PayloadLen]
}
