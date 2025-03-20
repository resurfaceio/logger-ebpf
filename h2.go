package main

import "encoding/binary"

const (
	DATA byte = iota
	HEADERS
	PRIORITY
	RST_STREAM
	SETTINGS
	PUSH_PROMISE
	PING
	GOAWAY
	WINDOW_UPDATE
	CONTINUATION
	ALTSVC
	ORIGIN
)

type h2frame struct {
	_len       [3]byte
	_lend      uint32
	_type      byte
	_flag      byte
	_streamID  [4]byte
	_streamIDd uint32
	_data      []byte
	_empty     bool
	_raw       []byte
}

func toh2frame(barray []byte, offset int) (frame h2frame, nextIndex int) {
	if offset+3 > len(barray) {
		nextIndex = -1
		frame._empty = true
		return
	}
	copy(frame._len[:], barray[offset:3+offset])

	tmp := make([]byte, 4)
	copy(tmp[1:], frame._len[:])
	frame._lend = binary.BigEndian.Uint32(tmp)

	nextIndex = 9 + offset + int(frame._lend)
	if nextIndex > len(barray) {
		nextIndex = -1
		frame._empty = true
		return
	}

	frame._type = barray[3+offset]

	frame._flag = barray[4+offset]

	copy(frame._streamID[:], barray[5+offset:9+offset])

	copy(tmp[:], frame._streamID[:])
	frame._streamIDd = binary.BigEndian.Uint32(tmp)

	frame._empty = (frame._lend+uint32(frame._type)+uint32(frame._flag)+frame._streamIDd == 0)
	if !frame._empty {
		frame._data = make([]byte, frame._lend)
		copy(frame._data, barray[9+offset:nextIndex])

		frame._raw = make([]byte, nextIndex-offset)
		copy(frame._raw, barray[offset:nextIndex])
	}

	return
}

func toFrames(frameBytes []byte) (frames []h2frame) {
	var frame h2frame
	var offset int = 0
	for offset < len(frameBytes) {
		frame, offset = toh2frame(frameBytes, offset)
		if offset == -1 {
			break
		}
		if !frame._empty {
			frames = append(frames, frame)
		}
	}

	return
}
