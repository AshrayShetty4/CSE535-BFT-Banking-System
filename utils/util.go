package utils

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func VoteKey(replicaID uint64, digest []byte) string {
	return hex.EncodeToString(digest) + "|" + fmt.Sprint(replicaID)
}

func MatchingReplicaCount(votes map[string]struct{}, digest []byte) int {
	dPrefix := string(digest) + "|"
	cnt := 0
	for k := range votes {
		if strings.HasPrefix(k, dPrefix) {
			cnt++
		}
	}
	return cnt
}

func EqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ContainsUint64(xs []uint64, id uint64) bool {
	for _, v := range xs {
		if v == id {
			return true
		}
	}
	return false
}

func ToUint64Slice(m map[uint64]bool) []uint64 {
	if len(m) == 0 {
		return nil
	}
	out := make([]uint64, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func BumpStatus(entry *Log, want string) {
	order := map[string]int{"": 0, "PrePrepare": 1, "Prepare": 2, "Commit": 3, "Execute": 4}
	if order[want] > order[entry.Status] {
		entry.Status = want
	}
}

func StatusRank(s string) int {
	switch s {
	case "Executed":
		return 4
	case "Commit":
		return 3
	case "Prepare":
		return 2
	case "PrePrepare":
		return 1
	default:
		return 0
	}
}
