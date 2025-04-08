package main

import (
	"encoding/binary"
	"log"
)

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

func findStreamIndex(barray []byte, streams [][4]byte) int {
	if len(barray) < 9 {
		return -1
	}
	var id [4]byte
	copy(id[:], barray[:4])
	if contains(&streams, id) {
		return 0
	}
	for i, b := range barray[4:] {
		for _, stream := range streams {
			if stream[3] == b {
				copy(id[:], barray[i+1:i+5])
				log.Printf("[H2] Checking prospect id: [%x]", id)
				if isSameStream(stream, id) {
					return i + 1
				}
			}
		}
	}
	return -1
}

func toh2frame(barray []byte, offset int, streams *[][4]byte) (frame h2frame, nextIndex int) {
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

	if frame._streamIDd != 0 && !contains(streams, frame._streamID) {
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

func toFrames(frameBytes []byte, streams *[][4]byte) (frames []h2frame) {
	var frame h2frame
	var offset int = 0
	var lastOffset int
	var counter int = 0
	for offset < len(frameBytes) {
		lastOffset = offset
		frame, offset = toh2frame(frameBytes, lastOffset, streams)
		if offset == -1 {
			break
		}
		if offset == -2 {
			log.Println("[H2] frame length is greater than array length. Assuming frame is corrupted. Trying to find known stream IDs from offset:", lastOffset)
			if newOffset := findStreamIndex(frameBytes[lastOffset:], *streams); newOffset != -1 && newOffset+lastOffset >= 5 {
				offset = newOffset + lastOffset - 5
				log.Println("[H2] NEW OFFSET:", offset)
				counter++
			} else {
				log.Printf("[H2] DID NOT FIND KNOWN STREAM [% x]", frameBytes)
				break
			}
		}
		if !frame._empty {
			frames = append(frames, frame)
		}
		if counter > 5 {
			log.Printf("[H2] LOOPINGGG [% x]", frameBytes)
			// will loop if offset == -2 more than once, i.e. if the length specified by the new offset found - 5B is greater than the array length
			// which means we need to store lastFoundNewOffset and compare it to newOffset, and if they are equal, call findStreamIndex(framBytes[lastOffset+1:])
			// is there a better way?
			return
		}
	}

	return
}
