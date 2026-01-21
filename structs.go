package utils

import (
	pbftproto "pbft/proto"
)

type Log struct {
	Status           string
	View             uint64
	Seq              uint64
	Digest           []byte
	Primary          uint64
	Payload          *pbftproto.ClientRequest
	Acks             map[uint64][]byte
	QuorumPrePrepare []uint64 `json:"q_preprepare,omitempty"`
	QuorumPrepare    []uint64 `json:"q_prepare,omitempty"`
	Result           string
}

type AckInfo struct {
	View      uint64
	Seq       uint64
	Digest    []byte
	ReplicaID uint64
	Signature []byte
}
