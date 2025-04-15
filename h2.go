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

func isSameStream(stream [4]byte, id [4]byte) bool {
	for i, b := range id {
		if b != stream[i] {
			break
		}
		if i == 3 {
			return true
		}
	}
	return false
}

func contains(streams *[][4]byte, id [4]byte) bool {
	for _, stream := range *streams {
		if isSameStream(stream, id) {
			return true
		}
	}
	return false
}

func findKnownStream(barray []byte, streams *[][4]byte) int {
	if len(barray) < 4 {
		return -1
	}
	var id [4]byte
	for i, b := range barray[3:] {
		for _, stream := range *streams {
			if stream[3] == b {
				copy(id[:], barray[i:i+4])
				// log.Printf("[H2] Checking prospect id: [% x] against stream ID: [% x]", id, stream)
				if isSameStream(stream, id) {
					return i
				}
			}
		}
	}
	return -1
}

func findValidLen(barray []byte) int {
	blen := uint32(len(barray))
	if blen < 3 {
		return -1
	}

	tmp := make([]byte, 4)
	for i := range blen - 2 {
		copy(tmp[1:], barray[i:i+3])
		if binary.BigEndian.Uint32(tmp) < blen {
			return int(i)
		}
	}

	return -1
}

func lookupNextFrame(barrayp *[]byte, offset int, streams *[][4]byte) int {
	if len(*barrayp) < offset+9 {
		return -1
	}
	if i := findKnownStream((*barrayp)[offset+5:], streams); i != -1 {
		return i + offset
	} else if i := findValidLen(*barrayp); i != -1 {
		return i + offset
	}
	return -1
}

func toh2frame(barrayp *[]byte, offset int, streams *[][4]byte) (frame h2frame, nextIndex int) {
	barray := *barrayp
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
		nextIndex = -2
		frame._empty = true
		return
	}

	frame._type = barray[3+offset]

	frame._flag = barray[4+offset]

	copy(frame._streamID[:], barray[5+offset:9+offset])

	copy(tmp[:], frame._streamID[:])
	frame._streamIDd = binary.BigEndian.Uint32(tmp)

	if !contains(streams, frame._streamID) {
		*streams = append(*streams, frame._streamID)
	}

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
	streams := make([][4]byte, 0, 5)
	offset := 0
	for offset < len(frameBytes) {
		frame, n := toh2frame(&frameBytes, offset, &streams)
		if n == -1 {
			break
		}
		if n == -2 {
			// log.Printf("[H2] frame length is greater than the length of array %p. Assuming frame is corrupted. Trying to find known stream IDs from offset: %d", &frameBytes, offset+1)
			if n = lookupNextFrame(&frameBytes, offset+1, &streams); n == -1 {
				// log.Printf("[H2] COULD NOT FIND KNOWN STREAM [% x]", frameBytes)
				break
			}
			// log.Println("[H2] NEW OFFSET:", n)
		}
		if !frame._empty {
			frames = append(frames, frame)
		}
		offset = n
	}

	return
}
