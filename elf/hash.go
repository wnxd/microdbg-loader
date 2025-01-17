package elf

import (
	"io"
)

type elfHashTable struct {
	buckets []uint32
	chains  []uint32
}

type gnuHashTable struct {
	symbias uint32
	shift   uint32
	indexes []uint64
	buckets []uint32
	sr      *io.SectionReader
	chains  []uint32
}

func elfHash(name string) uint32 {
	var h uint32
	for _, v := range []byte(name) {
		h = (h << 4) + uint32(v)
		g := h & 0xf0000000
		if g != 0 {
			h ^= g >> 24
			h &= ^g
		}
	}
	return h
}

func gnuHash(name string) uint32 {
	var h uint32 = 5381
	for _, v := range []byte(name) {
		h += (h << 5) + uint32(v)
	}
	return h & 0xffffffff
}
