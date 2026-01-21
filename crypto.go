package utils

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	pbftproto "pbft/proto"
	"sort"
)

func ComputeRequestDigest(req *pbftproto.ClientRequest) []byte {
	h := sha256.New()
	h.Write([]byte(req.From))
	h.Write([]byte{0})
	h.Write([]byte(req.To))
	h.Write([]byte{0})

	amtBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(amtBuf, req.Amount)
	h.Write(amtBuf)
	h.Write([]byte{0})

	h.Write([]byte(req.Timestamp))
	return h.Sum(nil)
}

func EncodeForSign(view, seq uint64, digest []byte) []byte {
	buf := make([]byte, 16+len(digest))
	binary.BigEndian.PutUint64(buf[0:8], view)
	binary.BigEndian.PutUint64(buf[8:16], seq)
	copy(buf[16:], digest)
	return buf
}

type Hasher struct {
	h hash.Hash
}

func NewHasher() *Hasher {
	return &Hasher{h: sha256.New()}
}

func (hh *Hasher) WriteUint64(v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	hh.h.Write(buf[:])
}

func (hh *Hasher) WriteBytes(b []byte) {
	if b != nil {
		hh.h.Write(b)
	}
}

func (hh *Hasher) WriteString(s string) {
	hh.h.Write([]byte(s))
}

func (hh *Hasher) Sum() []byte {
	return hh.h.Sum(nil)
}

func ComputeViewChangeDigest(msg *pbftproto.ViewChangeMsg) []byte {
	h := sha256.New()

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], msg.NewView)
	h.Write(buf[:])

	if msg.Checkpoint != nil {
		binary.BigEndian.PutUint64(buf[:], msg.Checkpoint.Seq)
		h.Write(buf[:])
	} else {
		binary.BigEndian.PutUint64(buf[:], 0)
		h.Write(buf[:])
	}

	entries := append([]*pbftproto.ViewChangeEntry(nil), msg.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Seq == entries[j].Seq {
			return entries[i].View < entries[j].View
		}
		return entries[i].Seq < entries[j].Seq
	})

	for _, e := range entries {
		binary.BigEndian.PutUint64(buf[:], e.Seq)
		h.Write(buf[:])
		binary.BigEndian.PutUint64(buf[:], e.View)
		h.Write(buf[:])
		h.Write(e.Digest)
	}

	return h.Sum(nil)
}
