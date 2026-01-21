package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	pbftproto "pbft/proto"
	crypto "pbft/utils"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	PhasePrePrepare = "preprepare"
	PhasePrepare    = "prepare"
	PhaseCommit     = "commit"
)

type phaseKey struct {
	Phase string
	View  uint64
	Seq   uint64
}

type Node struct {
	// protocol identity
	ID     uint64
	View   uint64
	Seq    uint64
	LowWM  uint64
	HighWM uint64

	ackChans     map[phaseKey]chan crypto.AckInfo
	completedAck map[phaseKey]bool
	ackChansMu   sync.Mutex

	// crypto
	PrivKey ed25519.PrivateKey
	PubKeys map[uint64]ed25519.PublicKey

	// replica state
	Log map[uint64]*crypto.Log
	// ViewChangeRecords map[uint64]ViewChangeInfo
	DB map[string]uint64

	// fault-injection flags
	Disabled        bool
	InDarkAttack    bool
	DarkPeers       map[uint64]bool
	Equivocation    bool
	EquivocatePeers map[uint64]bool
	Crash           bool
	TimeAttack      bool
	SignatureAttack bool

	logMu sync.RWMutex

	// networking handles
	ReplicaClients map[uint64]pbftproto.ReplicaServiceClient
	PrimaryClients map[uint64]pbftproto.PrimaryServiceClient

	PendingView  uint64
	InViewChange bool

	viewChangeMu   sync.Mutex
	viewChangeMsgs map[uint64]map[uint64]*pbftproto.ViewChangeMsg

	// primary-side aggregation state:
	mu            sync.Mutex
	quorumReached map[uint64]bool

	TotalNodes uint64

	// Request timer (for backups) to trigger view change on timeout.
	timerMu       sync.Mutex
	timerActive   bool
	timerCancel   context.CancelFunc
	timerForSeq   uint64
	timerDuration time.Duration

	// View-change/New-View history
	viewHistMu  sync.Mutex
	ViewHistory []*pbftproto.NewViewMsg

	// Exactly-once execution tracking (by request digest)
	executedMu sync.Mutex
	Executed   map[string]bool

	// Optimistic fast-path
	OptimisticFastPath bool
	fastPathTimeout    time.Duration
}

func (n *Node) isDark(peerID uint64) bool {
	if !n.InDarkAttack || n.DarkPeers == nil {
		return false
	}
	n.mu.Lock()
	ok := n.DarkPeers[peerID]
	n.mu.Unlock()
	return ok
}

func (n *Node) isEquivTarget(peerID uint64) bool {
	if !n.Equivocation || n.EquivocatePeers == nil {
		return false
	}
	return n.EquivocatePeers[peerID]
}

func (n *Node) primaryForView(view uint64) uint64 {
	if n.TotalNodes == 0 {
		return 1
	}
	return (view % n.TotalNodes) + 1
}

func (n *Node) primarySendPrepareTo(ctx context.Context, rid uint64, view, seq uint64, digest []byte, quorumIds []uint64) {
	n.mu.Lock()
	cli := n.ReplicaClients[rid]
	n.mu.Unlock()
	if cli == nil || rid == n.ID {
		return
	}
	if n.InDarkAttack && n.isDark(rid) {
		return
	}

	if n.Crash {
		return
	}

	go func() {
		n.leaderSleepIfTimingAttack()

		sig := n.signMaybeCorrupt(view, seq, digest)
		msg := &pbftproto.PrepareMsg{
			View:      view,
			Seq:       seq,
			Digest:    digest,
			PrimaryId: n.ID,
			Signature: sig,
			QuorumIds: append([]uint64(nil), quorumIds...),
		}
		if _, err := cli.HandlePrepare(ctx, msg); err != nil {
			log.Printf("primary->%d HandlePrepare err: %v", rid, err)
		}
	}()
}

func (n *Node) primarySendCommitTo(ctx context.Context, rid uint64, view, seq uint64, digest []byte, quorumIds []uint64) {
	n.mu.Lock()
	cli := n.ReplicaClients[rid]
	n.mu.Unlock()
	if cli == nil || rid == n.ID {
		return
	}
	if n.InDarkAttack && n.isDark(rid) {
		return
	}

	if n.Crash {
		return
	}

	go func() {
		n.leaderSleepIfTimingAttack()

		sig := n.signMaybeCorrupt(view, seq, digest)
		msg := &pbftproto.CommitMsg{
			View:      view,
			Seq:       seq,
			Digest:    digest,
			PrimaryId: n.ID,
			Signature: sig,
			QuorumIds: append([]uint64(nil), quorumIds...),
		}
		if _, err := cli.HandleCommit(ctx, msg); err != nil {
			log.Printf("primary->%d HandleCommit err: %v", rid, err)
		}
	}()
}

func (n *Node) startPreprepareCollector(ctx context.Context, viewLocal, seqLocal uint64, digestLocal []byte) {
	ackChan := n.getAckChan(PhasePrePrepare, viewLocal, seqLocal)
	if ackChan == nil {
		return
	}
	ctxCollect, cancel := context.WithTimeout(ctx, 5*time.Second)
	go func() {
		defer cancel()
		votes := map[uint64]bool{n.ID: true}
		startedPrepare := false
		fastCommitted := false
		expected := int(n.TotalNodes)
		for {
			select {
			case ack := <-ackChan:
				if ack.View != viewLocal || ack.Seq != seqLocal {
					continue
				}
				if !crypto.EqualBytes(ack.Digest, digestLocal) {
					continue
				}
				if !votes[ack.ReplicaID] {
					votes[ack.ReplicaID] = true
					if startedPrepare {
						ids := crypto.ToUint64Slice(votes)
						n.primarySendPrepareTo(ctx, ack.ReplicaID, viewLocal, seqLocal, digestLocal, ids)
					}
					log.Printf("[node %d] %s seq=%d new ACK from %d (total=%d)",
						n.ID, PhasePrePrepare, seqLocal, ack.ReplicaID, len(votes))
				}

				if n.sbftAllowed() && !fastCommitted && len(votes) == expected {
					fastCommitted = true
					allIDs := make([]uint64, 0, expected)
					for id := range n.PubKeys {
						allIDs = append(allIDs, id)
					}
					sort.Slice(allIDs, func(i, j int) bool { return allIDs[i] < allIDs[j] })
					n.logMu.Lock()
					if e := n.Log[seqLocal]; e != nil {
						if e.Status == "" {
							crypto.BumpStatus(e, "PrePrepare")
						}
						crypto.BumpStatus(e, "Commit")
						e.QuorumPrePrepare = append([]uint64(nil), allIDs...)
					}
					n.logMu.Unlock()
					log.Printf("[node %d] FAST-PATH (PrePrepare quorum ALL) seq=%d -> Commit+Execute then broadcast Commit", n.ID, seqLocal)

					n.executeTxn()
					n.writeDBJSON()
					n.PrintLogSnapshot("FAST-PATH PREPREPARE (primary)", seqLocal)

					go n.PrimaryBroadcastCommit(ctx, viewLocal, seqLocal, digestLocal, allIDs)

					n.finalizeAckChan(PhasePrePrepare, viewLocal, seqLocal)
					return
				}
				if !startedPrepare && len(votes) >= 5 {
					startedPrepare = true
					ids := crypto.ToUint64Slice(votes)
					n.logMu.Lock()
					if e := n.Log[seqLocal]; e != nil {
						if e.Status == "" {
							crypto.BumpStatus(e, "PrePrepare")
						}
						e.QuorumPrePrepare = append([]uint64(nil), ids...)
					}
					n.logMu.Unlock()
					n.PrintLogSnapshot("after PREPREPARE quorum (primary)", seqLocal)
					go n.PrimaryBroadcastPrepare(context.Background(), viewLocal, seqLocal, digestLocal, ids)
				}
			case <-ctxCollect.Done():
				n.finalizeAckChan(PhasePrePrepare, viewLocal, seqLocal)
				return
			}
		}
	}()
}

func (n *Node) leaderSleepIfTimingAttack() {
	if n.TimeAttack {
		time.Sleep(time.Duration(10) * time.Millisecond)
	}
}

func (n *Node) sbftAllowed() bool {
	if !n.OptimisticFastPath {
		return false
	}
	n.mu.Lock()
	disabled := n.Disabled || n.Crash || n.InDarkAttack || n.Equivocation || n.SignatureAttack || n.TimeAttack
	total := n.TotalNodes

	rep := make(map[uint64]pbftproto.ReplicaServiceClient, len(n.ReplicaClients))
	for id, cli := range n.ReplicaClients {
		rep[id] = cli
	}
	var dark map[uint64]bool
	if n.DarkPeers != nil {
		dark = make(map[uint64]bool, len(n.DarkPeers))
		for id, v := range n.DarkPeers {
			dark[id] = v
		}
	}
	n.mu.Unlock()
	if disabled || total == 0 {
		return false
	}

	peers := 0
	for id := range n.PubKeys {
		if id == n.ID {
			continue
		}
		if dark != nil && dark[id] {
			return false
		}
		if rep[id] == nil {
			return false
		}
		peers++
	}
	return peers == int(total-1)
}

func (n *Node) PrimaryBroadcastPrePrepare(ctx context.Context, req *pbftproto.ClientRequest) error {
	fmt.Println("PrimaryBroadcastPrePrepare :: starting PrePrepare broadcast for request:", req)
	if n.Disabled {
		log.Printf("[node %d] disabled: ignoring PrePrepare broadcast", n.ID)
		return nil
	}

	viewLocal, seqLocal := n.nextSeq()

	digest := crypto.ComputeRequestDigest(&pbftproto.ClientRequest{
		From:      req.From,
		To:        req.To,
		Amount:    req.Amount,
		Timestamp: req.Timestamp,
	})

	digestLocal := digest

	if !n.Equivocation || len(n.EquivocatePeers) == 0 {
		entry := &crypto.Log{
			Status:  "PrePrepare",
			View:    n.View,
			Seq:     seqLocal,
			Digest:  digestLocal,
			Primary: n.ID,
			Payload: &pbftproto.ClientRequest{
				From: req.From, To: req.To, Amount: req.Amount, Timestamp: req.Timestamp,
			},
		}
		n.logMu.Lock()
		n.Log[seqLocal] = entry
		n.logMu.Unlock()
		n.PrintLogSnapshot("PREPREPARE (primary)", seqLocal)

		// start single collector
		n.startPreprepareCollector(ctx, viewLocal, seqLocal, digestLocal)

		// fan-out to all replicas with the same seq
		n.leaderSleepIfTimingAttack()
		for rid, cli := range n.ReplicaClients {
			if rid == n.ID || cli == nil {
				continue
			}
			if n.InDarkAttack && n.isDark(rid) {
				log.Printf("[node %d] IN-DARK: skipping PrePrepare to %d (seq=%d)", n.ID, rid, seqLocal)
				continue
			}
			ridLocal, c := rid, cli
			go func() {
				msg := &pbftproto.PrePrepareMsg{
					View:      viewLocal,
					Seq:       seqLocal,
					Digest:    digestLocal,
					PrimaryId: n.ID,
					Signature: n.signMaybeCorrupt(viewLocal, seqLocal, digestLocal),
					Request:   req,
				}
				if _, err := c.HandlePrePrepare(ctx, msg); err != nil {
					log.Printf("primary->replica %d HandlePrePrepare error: %v", ridLocal, err)
				}
			}()
		}
		return nil
	}

	seqA := seqLocal
	_, seqB := n.nextSeq()
	viewA := viewLocal
	viewB := viewLocal

	eA := &crypto.Log{
		Status: "PrePrepare", View: viewA, Seq: seqA, Digest: digestLocal, Primary: n.ID,
		Payload: &pbftproto.ClientRequest{From: req.From, To: req.To, Amount: req.Amount, Timestamp: req.Timestamp},
	}
	eB := &crypto.Log{
		Status: "PrePrepare", View: viewB, Seq: seqB, Digest: digestLocal, Primary: n.ID,
		Payload: &pbftproto.ClientRequest{From: req.From, To: req.To, Amount: req.Amount, Timestamp: req.Timestamp},
	}
	n.logMu.Lock()
	n.Log[seqA] = eA
	n.Log[seqB] = eB
	n.logMu.Unlock()
	n.PrintLogSnapshot("PREPREPARE (primary-EQUIV A)", seqA)
	n.PrintLogSnapshot("PREPREPARE (primary-EQUIV B)", seqB)

	n.startPreprepareCollector(ctx, viewA, seqA, digestLocal)
	n.startPreprepareCollector(ctx, viewB, seqB, digestLocal)

	n.leaderSleepIfTimingAttack()
	type rc struct {
		id  uint64
		cli pbftproto.ReplicaServiceClient
	}
	var snap []rc
	n.mu.Lock()
	if len(n.ReplicaClients) > 0 {
		snap = make([]rc, 0, len(n.ReplicaClients))
		for rid, cli := range n.ReplicaClients {
			snap = append(snap, rc{rid, cli})
		}
	}
	n.mu.Unlock()
	for _, it := range snap {
		ridLocal, c := it.id, it.cli
		if ridLocal == n.ID || c == nil {
			continue
		}
		if n.InDarkAttack && n.isDark(ridLocal) {
			log.Printf("[node %d] IN-DARK: skipping PrePrepare to %d (seq=%d/%d)", n.ID, ridLocal, seqA, seqB)
			continue
		}
		go func() {
			seqSend := seqB
			if n.isEquivTarget(ridLocal) {
				seqSend = seqA
			}
			msg := &pbftproto.PrePrepareMsg{
				View:      viewLocal,
				Seq:       seqSend,
				Digest:    digestLocal,
				PrimaryId: n.ID,
				Signature: n.signMaybeCorrupt(viewLocal, seqSend, digestLocal),
				Request:   req,
			}
			if _, err := c.HandlePrePrepare(ctx, msg); err != nil {
				log.Printf("primary->replica %d HandlePrePrepare error: %v", ridLocal, err)
			}
		}()
	}
	return nil
}

func (n *Node) PrimaryBroadcastPrepare(ctx context.Context, view, seq uint64, digest []byte, initialTargets []uint64) {
	if n.Disabled || n.Crash {
		log.Printf("[node %d] disabled: ignoring Prepare broadcast", n.ID)
		return
	}

	ackChan := n.getAckChan(PhasePrepare, view, seq)
	if ackChan == nil {
		return
	}

	ids := append([]uint64(nil), initialTargets...)
	for _, rid := range ids {
		if rid == n.ID {
			continue
		}
		n.primarySendPrepareTo(ctx, rid, view, seq, digest, ids)
	}

	ctxCollect, cancel := context.WithTimeout(ctx, 5*time.Second)

	go func() {
		responders := make(map[uint64]bool, len(ids)+1)
		for _, id := range ids {
			responders[id] = true
		}
		responders[n.ID] = true
		startedCommit := false
		fastWindowPassed := false
		var fastTimer *time.Timer
		sbftOk := n.sbftAllowed()
		if sbftOk && n.fastPathTimeout > 0 {
			fastTimer = time.NewTimer(n.fastPathTimeout)
			defer fastTimer.Stop()
			log.Printf("[node %d] FAST-PATH window started for seq=%d (timeout=%v)", n.ID, seq, n.fastPathTimeout)
		}
		expected := int(n.TotalNodes)
		for {
			select {
			case ack := <-ackChan:
				if ack.View != view || ack.Seq != seq {
					continue
				}
				if !crypto.EqualBytes(ack.Digest, digest) {
					continue
				}
				if !responders[ack.ReplicaID] {
					responders[ack.ReplicaID] = true
					if startedCommit {
						cids := crypto.ToUint64Slice(responders)
						n.primarySendCommitTo(ctx, ack.ReplicaID, view, seq, digest, cids)
					}
				}
				if sbftOk && !startedCommit && len(responders) == expected {
					startedCommit = true
					allIDs := make([]uint64, 0, expected)
					for id := range n.PubKeys {
						allIDs = append(allIDs, id)
					}
					sort.Slice(allIDs, func(i, j int) bool { return allIDs[i] < allIDs[j] })
					n.logMu.Lock()
					if e := n.Log[seq]; e != nil {
						crypto.BumpStatus(e, "Commit")
						e.QuorumPrepare = append([]uint64(nil), allIDs...)
					}
					n.logMu.Unlock()
					n.PrintLogSnapshot("after PREPARE quorum (FAST primary)", seq)
					go n.PrimaryBroadcastCommit(ctx, view, seq, digest, allIDs)
					continue
				}
				if (!sbftOk || fastWindowPassed) && !startedCommit && len(responders) >= 5 {
					startedCommit = true
					cids := crypto.ToUint64Slice(responders)
					n.logMu.Lock()
					if e := n.Log[seq]; e != nil {
						crypto.BumpStatus(e, "Commit")
						e.QuorumPrepare = append([]uint64(nil), cids...)
					}
					n.logMu.Unlock()
					n.PrintLogSnapshot("after PREPARE quorum (primary)", seq)
					go n.PrimaryBroadcastCommit(ctx, view, seq, digest, cids)
				}
			case <-func() <-chan time.Time {
				if fastTimer != nil {
					return fastTimer.C
				}
				return make(chan time.Time)
			}():
				fastWindowPassed = true
				log.Printf("[node %d] FAST-PATH window expired for seq=%d; waiting for 2f+1 to use SLOW-PATH", n.ID, seq)
			case <-ctxCollect.Done():
				log.Printf("[node %d] PREPARE collector done for seq=%d (acks=%d)", n.ID, seq, len(responders))
				n.finalizeAckChan(PhasePrepare, view, seq)
				cancel()
				return
			}
		}
	}()

}

func (n *Node) PrimaryBroadcastCommit(ctx context.Context, view, seq uint64, digest []byte, prepQuorum []uint64) {
	if n.Disabled || n.Crash {
		log.Printf("[node %d] disabled: ignoring Commit broadcast", n.ID)
		return
	}

	sig := n.signMaybeCorrupt(view, seq, digest)

	msg := &pbftproto.CommitMsg{
		View:      view,
		Seq:       seq,
		Digest:    digest,
		PrimaryId: n.ID,
		Signature: sig,
		QuorumIds: prepQuorum,
	}

	n.leaderSleepIfTimingAttack()

	type rc3 struct {
		id  uint64
		cli pbftproto.ReplicaServiceClient
	}
	var snap []rc3
	n.mu.Lock()
	if len(n.ReplicaClients) > 0 {
		snap = make([]rc3, 0, len(n.ReplicaClients))
		for rid, cli := range n.ReplicaClients {
			snap = append(snap, rc3{rid, cli})
		}
	}
	n.mu.Unlock()

	n.logMu.Lock()
	e := n.Log[seq]
	n.logMu.Unlock()
	n.executeTxn()
	n.writeDBJSON()

	fast := (len(prepQuorum) == int(n.TotalNodes))
	if fast {
		log.Printf("[node %d] COMMIT broadcast FAST-PATH seq=%d recipients=%d", n.ID, seq, len(snap))
	} else {
		log.Printf("[node %d] COMMIT broadcast SLOW-PATH seq=%d recipients=%d quorumSize=%d", n.ID, seq, len(snap), len(prepQuorum))
	}
	for _, it := range snap {
		rid, c := it.id, it.cli
		if rid == n.ID || c == nil {
			continue
		}
		if n.isDark(rid) {
			log.Printf("[node %d] IN-DARK: skipping Commit to %d (seq=%d)", n.ID, rid, seq)
			continue
		}
		if n.Crash {
			break
		}
		go func() {
			if _, err := c.HandleCommit(ctx, msg); err != nil {
				log.Printf("primary->replica %d HandleCommit error: %v", rid, err)
			}
		}()
	}

	n.PrintLogSnapshot("after Executing quorum (primary)", seq)
	if n.Crash {
		return
	}

	n.logMu.RLock()
	e = n.Log[seq]
	n.logMu.RUnlock()

	if e != nil {
		success := (e.Result == "" || e.Result == "ok")
		msg := e.Result
		if msg == "" && success {
			msg = "ok"
		}
		n.sendClientReplyFor(seq, success, msg)
	}

}

// func (n *Node) deleteAckChan(phase string, view, seq uint64) {
// 	n.ackChansMu.Lock()
// 	defer n.ackChansMu.Unlock()
// 	delete(n.ackChans, phaseKey{Phase: phase, View: view, Seq: seq})
// }

func (n *Node) signPrePrepare(view, seq uint64, digest []byte) ([]byte, error) {
	msg := crypto.EncodeForSign(view, seq, digest)
	sig := ed25519.Sign(n.PrivKey, msg)
	return sig, nil
}

func (n *Node) signMaybeCorrupt(view, seq uint64, digest []byte) []byte {
	sig, _ := n.signPrePrepare(view, seq, digest)
	if !n.SignatureAttack {
		return sig
	}
	if len(sig) > 0 {
		sig2 := make([]byte, len(sig))
		copy(sig2, sig)
		sig2[0] ^= 0xFF
		return sig2
	}
	return sig
}

func (n *Node) verifyPrePrepareSig(senderID uint64, view, seq uint64, digest, sig []byte) bool {
	pub, ok := n.PubKeys[senderID]
	if !ok {
		return false
	}
	msg := crypto.EncodeForSign(view, seq, digest)
	return ed25519.Verify(pub, msg, sig)
}

func (n *Node) startRequestTimer(seq uint64) {
	n.timerMu.Lock()
	if n.timerActive {
		n.timerMu.Unlock()
		return
	}
	d := n.timerDuration
	if d <= 0 {
		d = 2 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.timerActive = true
	n.timerCancel = cancel
	n.timerForSeq = seq
	n.timerMu.Unlock()

	go func(viewAtStart uint64) {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			n.timerMu.Lock()
			active := n.timerActive && n.timerForSeq == seq

			n.timerActive = false
			n.timerCancel = nil
			n.timerForSeq = 0
			n.timerMu.Unlock()
			if active {
				n.mu.Lock()
				baseView := n.View
				if n.PendingView > baseView {
					baseView = n.PendingView
				}
				nextView := baseView + 1
				n.mu.Unlock()
				log.Printf("[node %d] request timer expired for seq=%d; starting view-change to v=%d", n.ID, seq, nextView)
				n.StartViewChange(nextView)
				n.startRequestTimer(seq)
			}
		case <-ctx.Done():
			return
		}
	}(n.View)
}

func (n *Node) retargetTimerToSeq(seq uint64) {
	n.timerMu.Lock()
	if n.timerActive {
		if n.timerCancel != nil {
			n.timerCancel()
		}
		n.timerActive = false
		n.timerCancel = nil
		n.timerForSeq = 0
	}
	n.timerMu.Unlock()
	n.startRequestTimer(seq)
}

func (n *Node) retargetTimerToMinPending() {
	var minSeq uint64
	n.logMu.RLock()
	for s, e := range n.Log {
		if e == nil {
			continue
		}
		if strings.ToLower(e.Status) != "execute" {
			if minSeq == 0 || s < minSeq {
				minSeq = s
			}
		}
	}
	n.logMu.RUnlock()

	n.timerMu.Lock()
	active := n.timerActive
	cur := n.timerForSeq
	cancel := n.timerCancel
	n.timerMu.Unlock()

	if minSeq == 0 {
		n.timerMu.Lock()
		if active && cancel != nil {
			cancel()
		}
		n.timerActive = false
		n.timerCancel = nil
		n.timerForSeq = 0
		n.timerMu.Unlock()
		return
	}

	if !active {
		n.startRequestTimer(minSeq)
		return
	}
	if cur != minSeq {
		n.timerMu.Lock()
		if n.timerActive && n.timerCancel != nil {
			n.timerCancel()
		}
		n.timerActive = false
		n.timerCancel = nil
		n.timerForSeq = 0
		n.timerMu.Unlock()
		n.startRequestTimer(minSeq)
	}
}

// func (n *Node) stopRequestTimerIfSeq(seq uint64) {
// 	n.timerMu.Lock()
// 	if n.timerActive && n.timerForSeq == seq {
// 		if n.timerCancel != nil {
// 			n.timerCancel()
// 		}
// 		n.timerActive = false
// 		n.timerCancel = nil
// 		n.timerForSeq = 0
// 	}
// 	n.timerMu.Unlock()
// }

// func (n *Node) restartTimerIfWaitingOther() {
// 	// If there exists any other request still waiting to execute, start timer for its seq.
// 	// Choose the smallest seq with status not Execute.
// 	var minSeq uint64
// 	n.logMu.RLock()
// 	for s, e := range n.Log {
// 		if e == nil {
// 			continue
// 		}
// 		if e.Status != "Execute" {
// 			if minSeq == 0 || s < minSeq {
// 				minSeq = s
// 			}
// 		}
// 	}
// 	n.logMu.RUnlock()
// 	if minSeq != 0 {
// 		n.startRequestTimer(minSeq)
// 	}
// }

func (n *Node) executeTxn() {
	n.mu.Lock()
	defer n.mu.Unlock()

	var seq uint64 = 0
	for {
		n.logMu.RLock()
		entry, ok := n.Log[seq+1]
		n.logMu.RUnlock()
		if !ok {
			return
		}

		if entry == nil || entry.Payload == nil {
			n.logMu.Lock()
			e := n.Log[seq+1]
			if e != nil && strings.ToLower(e.Status) != "execute" {
				e.Result = "ok"
				crypto.BumpStatus(e, "Execute")
			}
			n.logMu.Unlock()
			seq++
			continue
		}

		n.logMu.RLock()
		status := entry.Status
		from := entry.Payload.From
		to := entry.Payload.To
		amount := entry.Payload.Amount
		dig := append([]byte(nil), entry.Digest...)
		n.logMu.RUnlock()

		switch status {
		case "Commit":
			if len(dig) > 0 {
				key := string(dig)
				n.executedMu.Lock()
				if n.Executed == nil {
					n.Executed = make(map[string]bool)
				}
				if n.Executed[key] {
					n.executedMu.Unlock()
					n.logMu.Lock()
					if e := n.Log[seq+1]; e != nil {
						e.Result = "ok"
						crypto.BumpStatus(e, "Execute")
					}
					n.logMu.Unlock()
					seq++
					continue
				}
				n.Executed[key] = true
				n.executedMu.Unlock()
			}

			if from == to {
				n.logMu.Lock()
				if e := n.Log[seq+1]; e != nil {
					e.Result = "ok"
					crypto.BumpStatus(e, "Execute")
				}
				n.logMu.Unlock()
				seq++
				continue
			}

			fromBal := n.DB[from]
			if fromBal < amount {
				n.logMu.Lock()
				if e := n.Log[seq+1]; e != nil {
					e.Result = "ok"
					crypto.BumpStatus(e, "Execute")
				}
				n.logMu.Unlock()
				seq++
				continue
			}

			n.DB[from] = fromBal - amount
			n.DB[to] = n.DB[to] + amount
			n.logMu.Lock()
			if e := n.Log[seq+1]; e != nil {
				e.Result = "ok"
				crypto.BumpStatus(e, "Execute")
			}
			n.logMu.Unlock()
			seq++
		case "Execute":
			seq++
		default:
			return
		}
	}
}

type PrimaryServer struct {
	Node *Node
	pbftproto.UnimplementedPrimaryServiceServer
}

func (n *Node) DefaultDB() {
	n.DB = make(map[string]uint64)
	for i := 'A'; i <= 'J'; i++ {
		n.DB[string(i)] = 10
	}
	n.writeDBJSON()
}

func (n *Node) writeDBJSON() {
	n.mu.Lock()
	id := n.ID
	out := make(map[string]uint64)
	for i := 'A'; i <= 'J'; i++ {
		k := string(i)
		if v, ok := n.DB[k]; ok {
			out[k] = v
		} else {
			out[k] = 0
		}
	}
	n.mu.Unlock()

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		log.Printf("[node %d] writeDBJSON marshal error: %v", id, err)
		return
	}
	if err := os.MkdirAll("db", 0755); err != nil {
		log.Printf("[node %d] writeDBJSON MkdirAll db/: %v", id, err)
		return
	}
	fname := fmt.Sprintf("db/db_%d.json", id)
	if err := os.WriteFile(fname, data, 0644); err != nil {
		log.Printf("[node %d] writeDBJSON WriteFile %s: %v", id, fname, err)
		return
	}
}

func (n *Node) getAckChan(phase string, view, seq uint64) chan crypto.AckInfo {
	n.ackChansMu.Lock()
	defer n.ackChansMu.Unlock()
	k := phaseKey{Phase: phase, View: view, Seq: seq}
	if n.completedAck[k] {
		return nil
	}
	ch := n.ackChans[k]
	if ch == nil {
		ch = make(chan crypto.AckInfo, 32)
		n.ackChans[k] = ch
	}
	return ch
}

func (n *Node) lookupAckChan(phase string, view, seq uint64) (chan crypto.AckInfo, bool) {
	n.ackChansMu.Lock()
	defer n.ackChansMu.Unlock()
	ch, ok := n.ackChans[phaseKey{Phase: phase, View: view, Seq: seq}]
	return ch, ok
}

func (n *Node) finalizeAckChan(phase string, view, seq uint64) {
	n.ackChansMu.Lock()
	defer n.ackChansMu.Unlock()
	k := phaseKey{Phase: phase, View: view, Seq: seq}
	n.completedAck[k] = true
	delete(n.ackChans, k)
}

func (n *Node) nextSeq() (view uint64, seq uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Seq++
	return n.View, n.Seq
}

func (n *Node) PrintLogSnapshot(label string, seq uint64) {
	n.logMu.Lock()
	defer n.logMu.Unlock()
	e := n.Log[seq]

	if e == nil {
		log.Printf("[node %d] %s | seq=%d: <no log entry>\n", n.ID, label, seq)
		return
	}

	fmt.Println("\n\n\nLog is:")
	for key, val := range n.Log {
		fmt.Printf("Key: %d, {\n", key)
		fmt.Printf("  Status: %s\n", val.Status)
		fmt.Printf("  View: %d\n", val.View)
		fmt.Printf("  Seq: %d\n", val.Seq)
		fmt.Printf("  Primary: %d\n", val.Primary)
		fmt.Printf("  Payload: %+v\n", val.Payload)
		fmt.Println("}")
	}

}

func (ps *PrimaryServer) SendPrePrepareAck(ctx context.Context, ack *pbftproto.PrePrepareAck) (*pbftproto.AckReceipt, error) {
	fmt.Println("PrePrepare :: Start send pre prepare ack")
	n := ps.Node
	if n.Disabled || n.Crash {
		return &pbftproto.AckReceipt{Ok: false, Message: "primary disabled"}, nil
	}

	if !n.verifyPrePrepareSig(ack.ReplicaId, ack.View, ack.Seq, ack.Digest, ack.Signature) {
		fmt.Println("PrePrepare :: Couldnt verify signature from replica", ack.ReplicaId)
		return &pbftproto.AckReceipt{Ok: false, Message: "bad replica signature"}, nil
	}

	entry, ok := n.Log[ack.Seq]
	if !ok {
		return &pbftproto.AckReceipt{Ok: false, Message: "unknown seq"}, nil
	}

	if entry.View != ack.View {
		return &pbftproto.AckReceipt{Ok: false, Message: "view mismatch"}, nil
	}
	if !crypto.EqualBytes(entry.Digest, ack.Digest) {
		return &pbftproto.AckReceipt{Ok: false, Message: "digest mismatch"}, nil
	}

	n.mu.Lock()

	if entry.Acks == nil {
		entry.Acks = make(map[uint64][]byte)
	}
	entry.Acks[ack.ReplicaId] = ack.Signature
	n.mu.Unlock()

	n.deliverAck(PhasePrePrepare, ack.View, ack.Seq, crypto.AckInfo{
		View: ack.View, Seq: ack.Seq, Digest: ack.Digest,
		ReplicaID: ack.ReplicaId, Signature: ack.Signature,
	})

	n.logMu.RLock()
	e2 := n.Log[ack.Seq]
	var started bool
	var preQ []uint64
	if e2 != nil && len(e2.QuorumPrePrepare) > 0 {
		started = true
		preQ = append([]uint64(nil), e2.QuorumPrePrepare...)
	}
	n.logMu.RUnlock()
	if started {
		fmt.Printf("[node %d] Fallback-Prepare: late PrePrepareAck from %d for seq=%d; sending Prepare\n", n.ID, ack.ReplicaId, ack.Seq)
		n.primarySendPrepareTo(ctx, ack.ReplicaId, ack.View, ack.Seq, ack.Digest, preQ)
	}

	return &pbftproto.AckReceipt{Ok: true, Message: "ack recorded"}, nil
}

func (ps *PrimaryServer) SendPrepareAck(ctx context.Context, ack *pbftproto.PrepareAck) (*pbftproto.AckReceipt, error) {
	n := ps.Node
	if n.Disabled || n.Crash {
		return &pbftproto.AckReceipt{Ok: false, Message: "primary disabled"}, nil
	}

	// Verify replica signature on (v||n||d)
	if !n.verifyPrePrepareSig(ack.ReplicaId, ack.View, ack.Seq, ack.Digest, ack.Signature) {
		return &pbftproto.AckReceipt{Ok: false, Message: "bad replica signature"}, nil
	}

	// Match existing log entry
	entry, ok := n.Log[ack.Seq]
	if !ok || entry.View != ack.View || !crypto.EqualBytes(entry.Digest, ack.Digest) {
		return &pbftproto.AckReceipt{Ok: false, Message: "mismatch"}, nil
	}

	// Store ack for audit
	n.mu.Lock()
	if entry.Acks == nil {
		entry.Acks = make(map[uint64][]byte)
	}
	entry.Acks[ack.ReplicaId] = ack.Signature
	n.mu.Unlock()

	n.deliverAck(PhasePrepare, ack.View, ack.Seq, crypto.AckInfo{
		View: ack.View, Seq: ack.Seq, Digest: ack.Digest,
		ReplicaID: ack.ReplicaId, Signature: ack.Signature,
	})

	n.logMu.RLock()
	e3 := n.Log[ack.Seq]
	var startedCommit bool
	var prepQ []uint64
	if e3 != nil && len(e3.QuorumPrepare) > 0 {
		startedCommit = true
		prepQ = append([]uint64(nil), e3.QuorumPrepare...)
	}
	n.logMu.RUnlock()
	if startedCommit {
		fmt.Printf("[node %d] Fallback-Commit: late PrepareAck from %d for seq=%d; sending Commit\n", n.ID, ack.ReplicaId, ack.Seq)
		n.primarySendCommitTo(ctx, ack.ReplicaId, ack.View, ack.Seq, ack.Digest, prepQ)
	}

	return &pbftproto.AckReceipt{Ok: true, Message: "ack recorded"}, nil
}

func (ps *PrimaryServer) SendCommitAck(ctx context.Context, ack *pbftproto.CommitAck) (*pbftproto.AckReceipt, error) {
	n := ps.Node
	if n.Disabled || n.Crash {
		return &pbftproto.AckReceipt{Ok: false, Message: "primary disabled"}, nil
	}

	if !n.verifyPrePrepareSig(ack.ReplicaId, ack.View, ack.Seq, ack.Digest, ack.Signature) {
		return &pbftproto.AckReceipt{Ok: false, Message: "bad replica signature"}, nil
	}

	entry, ok := n.Log[ack.Seq]
	if !ok || entry.View != ack.View || !crypto.EqualBytes(entry.Digest, ack.Digest) {
		return &pbftproto.AckReceipt{Ok: false, Message: "mismatch"}, nil
	}

	n.mu.Lock()
	if entry.Acks == nil {
		entry.Acks = make(map[uint64][]byte)
	}
	entry.Acks[ack.ReplicaId] = ack.Signature
	n.mu.Unlock()

	n.deliverAck(PhaseCommit, ack.View, ack.Seq, crypto.AckInfo{
		View: ack.View, Seq: ack.Seq, Digest: ack.Digest,
		ReplicaID: ack.ReplicaId, Signature: ack.Signature,
	})

	return &pbftproto.AckReceipt{Ok: true, Message: "ack recorded"}, nil
}

func (n *Node) deliverAck(phase string, view, seq uint64, ai crypto.AckInfo) {
	if ch, ok := n.lookupAckChan(phase, view, seq); ok {
		select {
		case ch <- ai:
			return
		default:
		}
	}

	deadline := time.NewTimer(300 * time.Millisecond)
	tick := time.NewTicker(20 * time.Millisecond)
	defer deadline.Stop()
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			if ch, ok := n.lookupAckChan(phase, view, seq); ok {
				select {
				case ch <- ai:
					return
				default:
				}
			}
		case <-deadline.C:
			return
		}
	}
}

func (n *Node) BuildNewViewMsg(newView uint64) (*pbftproto.NewViewMsg, error) {
	n.viewChangeMu.Lock()
	vset, ok := n.viewChangeMsgs[newView]
	n.viewChangeMu.Unlock()

	if !ok || len(vset) == 0 {
		return nil, fmt.Errorf("no view-change messages for view %d", newView)
	}

	quorum := 5
	if len(vset) < quorum {
		return nil, fmt.Errorf("insufficient view-change messages: have %d need %d", len(vset), quorum)
	}

	cpSeq := uint64(0)

	type cand struct {
		seq  uint64
		view uint64
		dig  []byte
		stat string
	}

	chosen := make(map[uint64]*cand)

	for _, vc := range vset {
		for _, e := range vc.Entries {
			if e.Seq <= cpSeq {
				continue
			}
			c := chosen[e.Seq]
			if c == nil {
				chosen[e.Seq] = &cand{
					seq:  e.Seq,
					view: e.View,
					dig:  append([]byte(nil), e.Digest...),
					stat: e.Status,
				}
				continue
			}
			if crypto.StatusRank(e.Status) > crypto.StatusRank(c.stat) ||
				(crypto.StatusRank(e.Status) == crypto.StatusRank(c.stat) && e.View > c.view) {
				c.seq = e.Seq
				c.view = e.View
				c.dig = append([]byte(nil), e.Digest...)
				c.stat = e.Status
			}
		}
	}

	preps := make([]*pbftproto.NewViewPrePrepare, 0, len(chosen))
	n.logMu.RLock()
	for seq, c := range chosen {
		var req *pbftproto.ClientRequest
		if crypto.StatusRank(c.stat) >= crypto.StatusRank("Prepare") {
			if le, ok := n.Log[seq]; ok && le != nil && len(le.Digest) > 0 && string(le.Digest) == string(c.dig) {
				req = le.Payload
			}
		}
		preps = append(preps, &pbftproto.NewViewPrePrepare{
			View:    newView,
			Seq:     seq,
			Digest:  c.dig,
			Request: req,
		})
	}
	n.logMu.RUnlock()

	viewChanges := make([]*pbftproto.ViewChangeMsg, 0, len(vset))
	for _, m := range vset {
		viewChanges = append(viewChanges, m)
	}

	h := sha256.New()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], newView)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], n.ID)
	h.Write(buf[:])

	for _, vc := range viewChanges {
		d := crypto.ComputeViewChangeDigest(vc)
		h.Write(d)
	}
	for _, p := range preps {
		binary.BigEndian.PutUint64(buf[:], p.Seq)
		h.Write(buf[:])
		h.Write(p.Digest)
	}

	digest := h.Sum(nil)
	sig := ed25519.Sign(n.PrivKey, digest)

	return &pbftproto.NewViewMsg{
		NewView:     newView,
		PrimaryId:   n.ID,
		ViewChanges: viewChanges,
		PrePrepares: preps,
		Signature:   sig,
	}, nil
}

func (n *Node) BroadcastNewView(nv *pbftproto.NewViewMsg) {
	log.Printf("[node %d] broadcasting NEW-VIEW v=%d with %d pre-prepares", n.ID, nv.NewView, len(nv.PrePrepares))

	if err := n.applyNewView(nv); err != nil {
		log.Printf("[node %d] failed to apply local NEW-VIEW v=%d: %v", n.ID, nv.NewView, err)
	}

	n.viewHistMu.Lock()
	n.ViewHistory = append(n.ViewHistory, nv)
	n.viewHistMu.Unlock()

	type pc struct {
		id  uint64
		cli pbftproto.PrimaryServiceClient
	}
	var primaries []pc
	n.mu.Lock()
	if len(n.PrimaryClients) > 0 {
		primaries = make([]pc, 0, len(n.PrimaryClients))
		for rid, cli := range n.PrimaryClients {
			primaries = append(primaries, pc{rid, cli})
		}
	}
	n.mu.Unlock()

	for _, it := range primaries {
		ridLocal, c := it.id, it.cli
		fmt.Println("BroadcastNewView :: for client", ridLocal)
		if ridLocal == n.ID || c == nil {
			continue
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ack, err := c.HandleNewView(ctx, nv)
			if err != nil || !ack.Ok {
				log.Printf("[node %d] NEW-VIEW v=%d -> %d failed: %v, ack=%+v",
					n.ID, nv.NewView, ridLocal, err, ack)
			}
		}()
	}
}

func (ps *PrimaryServer) HandleNewView(ctx context.Context, msg *pbftproto.NewViewMsg) (*pbftproto.AckReceipt, error) {
	n := ps.Node
	if n.Disabled || n.Crash {
		return &pbftproto.AckReceipt{Ok: false, Message: "primary disabled"}, nil
	}

	expectedPrimary := n.primaryForView(msg.NewView)
	if msg.PrimaryId != expectedPrimary {
		return &pbftproto.AckReceipt{Ok: false, Message: "incorrect primary for view"}, nil
	}

	if msg.NewView < n.View {
		return &pbftproto.AckReceipt{Ok: false, Message: "stale new-view"}, nil
	}

	if !n.VerifyNewViewSignature(msg) {
		return &pbftproto.AckReceipt{Ok: false, Message: "invalid new-view signature"}, nil
	}

	if err := n.applyNewView(msg); err != nil {
		return &pbftproto.AckReceipt{Ok: false, Message: err.Error()}, nil
	}

	n.viewHistMu.Lock()
	n.ViewHistory = append(n.ViewHistory, msg)
	n.viewHistMu.Unlock()

	return &pbftproto.AckReceipt{Ok: true, Message: "new-view installed"}, nil
}

func (n *Node) VerifyNewViewSignature(msg *pbftproto.NewViewMsg) bool {
	pub, ok := n.PubKeys[msg.PrimaryId]
	if !ok {
		return false
	}

	h := sha256.New()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], msg.NewView)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], msg.PrimaryId)
	h.Write(buf[:])

	for _, vc := range msg.ViewChanges {
		d := crypto.ComputeViewChangeDigest(vc)
		h.Write(d)
	}
	for _, p := range msg.PrePrepares {
		binary.BigEndian.PutUint64(buf[:], p.Seq)
		h.Write(buf[:])
		h.Write(p.Digest)
	}

	digest := h.Sum(nil)
	return ed25519.Verify(pub, digest, msg.Signature)
}

func (n *Node) applyNewView(msg *pbftproto.NewViewMsg) error {
	type toSend struct {
		seq    uint64
		digest []byte
		req    *pbftproto.ClientRequest
	}
	var sends []toSend

	n.mu.Lock()
	if msg.NewView < n.View {
		n.mu.Unlock()
		return fmt.Errorf("already at higher view %d > %d", n.View, msg.NewView)
	}

	n.View = msg.NewView
	n.InViewChange = false
	n.PendingView = 0
	selfIsPrimary := (n.primaryForView(msg.NewView) == n.ID)
	n.mu.Unlock()

	n.logMu.Lock()
	for _, pp := range msg.PrePrepares {
		seq := pp.Seq
		entry, ok := n.Log[seq]
		if !ok || entry == nil {
			entry = &crypto.Log{}
			n.Log[seq] = entry
		}
		entry.View = msg.NewView
		entry.Seq = seq
		entry.Digest = append([]byte(nil), pp.Digest...)
		entry.Primary = msg.PrimaryId
		entry.Payload = pp.Request
		if entry.Status == "" || crypto.StatusRank(entry.Status) < crypto.StatusRank("PrePrepare") {
			entry.Status = "PrePrepare"
		}
		sends = append(sends, toSend{seq: seq, digest: append([]byte(nil), pp.Digest...), req: pp.Request})
	}
	n.logMu.Unlock()

	if selfIsPrimary {
		if n.Disabled || n.Crash {
			return nil
		}
		for _, s := range sends {
			n.startPreprepareCollector(context.Background(), msg.NewView, s.seq, s.digest)
			n.leaderSleepIfTimingAttack()
			type rc struct {
				id  uint64
				cli pbftproto.ReplicaServiceClient
			}
			var repls []rc
			n.mu.Lock()
			if len(n.ReplicaClients) > 0 {
				repls = make([]rc, 0, len(n.ReplicaClients))
				for rid, cli := range n.ReplicaClients {
					repls = append(repls, rc{rid, cli})
				}
			}
			n.mu.Unlock()
			for _, it := range repls {
				ridLocal, c := it.id, it.cli
				if ridLocal == n.ID || c == nil {
					continue
				}
				if n.InDarkAttack && n.isDark(ridLocal) {
					log.Printf("[node %d] IN-DARK: skipping NewView-PrePrepare to %d (seq=%d)", n.ID, ridLocal, s.seq)
					continue
				}
				seqLocal := s.seq
				digLocal := append([]byte(nil), s.digest...)
				reqLocal := s.req
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					m := &pbftproto.PrePrepareMsg{
						View:      msg.NewView,
						Seq:       seqLocal,
						Digest:    digLocal,
						PrimaryId: n.ID,
						Signature: n.signMaybeCorrupt(msg.NewView, seqLocal, digLocal),
						Request:   reqLocal,
					}
					if _, err := c.HandlePrePrepare(ctx, m); err != nil {
						log.Printf("[node %d] NewView->replica %d HandlePrePrepare error: %v", n.ID, ridLocal, err)
					}
				}()
			}
		}
	}

	n.executeTxn()
	n.writeDBJSON()

	n.retargetTimerToMinPending()

	return nil
}

func (n *Node) PrintFullLog() {
	n.logMu.RLock()
	keys := make([]int, 0, len(n.Log))
	for k := range n.Log {
		keys = append(keys, int(k))
	}
	n.logMu.RUnlock()
	sort.Ints(keys)
	log.Printf("[node %d] === LOG (entries=%d) ===", n.ID, len(keys))
	for _, k := range keys {
		seq := uint64(k)
		n.PrintLogSnapshot("LOG", seq)
	}
}

func (n *Node) PrintDBSimple() {
	n.mu.Lock()
	defer n.mu.Unlock()
	log.Printf("[node %d] === DB === %v", n.ID, n.DB)
}

func (n *Node) statusLabelFor(seq uint64) string {
	n.logMu.RLock()
	e := n.Log[seq]
	n.logMu.RUnlock()
	if e == nil || e.Status == "" {
		return "X"
	}
	switch strings.ToLower(e.Status) {
	case "preprepare":
		return "PP"
	case "prepare":
		return "P"
	case "commit":
		return "C"
	case "execute":
		return "E"
	default:
		return "X"
	}
}

func (n *Node) PrintStatusLabel(seq uint64) {
	lbl := n.statusLabelFor(seq)
	log.Printf("[node %d] Status for seq %d: %s", n.ID, seq, lbl)
}

func (n *Node) PrintViewHistory() {
	n.viewHistMu.Lock()
	defer n.viewHistMu.Unlock()
	log.Printf("[node %d] === VIEW HISTORY (count=%d) ===", n.ID, len(n.ViewHistory))
	for i, nv := range n.ViewHistory {
		if nv == nil {
			continue
		}
		log.Printf("[node %d] NewView[%d]: new_view=%d primary_id=%d preps=%d vchanges=%d",
			n.ID, i, nv.NewView, nv.PrimaryId, len(nv.PrePrepares), len(nv.ViewChanges))
		for _, vc := range nv.ViewChanges {
			if vc == nil {
				continue
			}
			ck := uint64(0)
			if vc.Checkpoint != nil {
				ck = vc.Checkpoint.Seq
			}
			log.Printf("  VC from %d for new_view=%d ckpt=%d entries=%d", vc.ReplicaId, vc.NewView, ck, len(vc.Entries))
		}

		for _, pp := range nv.PrePrepares {
			if pp == nil {
				continue
			}
			log.Printf("  PrePrepare v=%d seq=%d digestLen=%d reqNil=%v", pp.View, pp.Seq, len(pp.Digest), pp.Request == nil)
		}
	}
}

func (n *Node) buildLogString() string {
	n.logMu.RLock()
	keys := make([]int, 0, len(n.Log))
	for k := range n.Log {
		keys = append(keys, int(k))
	}
	n.logMu.RUnlock()
	sort.Ints(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "[node %d] === LOG (entries=%d) ===\n", n.ID, len(keys))
	for _, k := range keys {
		seq := uint64(k)
		n.logMu.RLock()
		e := n.Log[seq]
		n.logMu.RUnlock()
		if e == nil {
			continue
		}
		fmt.Fprintf(&b, "seq=%d status=%s view=%d primary=%d ", e.Seq, e.Status, e.View, e.Primary)
		if e.Payload != nil {
			fmt.Fprintf(&b, "req={from:%s to:%s amt:%d ts:%s}", e.Payload.From, e.Payload.To, e.Payload.Amount, e.Payload.Timestamp)
		} else {
			b.WriteString("req=<nil>")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (n *Node) buildDBString() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "[node %d] === DB ===\n", n.ID)
	for i := 'A'; i <= 'Z'; i++ {
		k := string(i)
		if v, ok := n.DB[k]; ok {
			fmt.Fprintf(&b, "%s:%d ", k, v)
		}
	}
	return b.String()
}

func (n *Node) buildViewString() string {
	n.viewHistMu.Lock()
	defer n.viewHistMu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "[node %d] === VIEW HISTORY (count=%d) ===\n", n.ID, len(n.ViewHistory))
	for i, nv := range n.ViewHistory {
		if nv == nil {
			continue
		}
		fmt.Fprintf(&b, "NewView[%d]: new_view=%d primary_id=%d preps=%d vchanges=%d\n", i, nv.NewView, nv.PrimaryId, len(nv.PrePrepares), len(nv.ViewChanges))
		for _, vc := range nv.ViewChanges {
			if vc == nil {
				continue
			}
			ck := uint64(0)
			if vc.Checkpoint != nil {
				ck = vc.Checkpoint.Seq
			}
			fmt.Fprintf(&b, "  VC from %d for new_view=%d ckpt=%d entries=%d\n", vc.ReplicaId, vc.NewView, ck, len(vc.Entries))
		}
		for _, pp := range nv.PrePrepares {
			if pp == nil {
				continue
			}
			fmt.Fprintf(&b, "  PrePrepare v=%d seq=%d digestLen=%d reqNil=%v\n", pp.View, pp.Seq, len(pp.Digest), pp.Request == nil)
		}
	}
	return b.String()
}

func (ps *PrimaryServer) ResetState(ctx context.Context, _ *pbftproto.ResetRequest) (*pbftproto.ResetReply, error) {
	n := ps.Node

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		getStr := func(key string) string {
			vals := md.Get(key)
			if len(vals) == 0 {
				return ""
			}
			return strings.TrimSpace(vals[0])
		}
		action := strings.ToLower(getStr("action"))
		if action != "" {
			switch action {
			case "print-log":
				n.PrintFullLog()
			case "print-db":
				n.PrintDBSimple()
			case "print-status":
				seqStr := getStr("seq")
				if seqStr != "" {
					if s, err := strconv.ParseUint(seqStr, 10, 64); err == nil {
						n.PrintStatusLabel(s)
					} else {
						log.Printf("[node %d] PrintStatus: bad seq %q", n.ID, seqStr)
					}
				}
			case "print-view":
				n.PrintViewHistory()
			default:
				log.Printf("[node %d] unknown admin action %q", n.ID, action)
			}
			return &pbftproto.ResetReply{Ok: true}, nil
		}
	}

	n.mu.Lock()
	n.View = 0
	n.Seq = 0
	n.InViewChange = false
	n.PendingView = 0

	n.timerMu.Lock()
	if n.timerCancel != nil {
		n.timerCancel()
	}
	n.timerActive = false
	n.timerCancel = nil
	n.timerForSeq = 0
	n.timerMu.Unlock()
	n.mu.Unlock()

	n.DefaultDB()

	n.logMu.Lock()
	n.Log = make(map[uint64]*crypto.Log)
	n.logMu.Unlock()

	n.ackChansMu.Lock()
	for k := range n.ackChans {
		delete(n.ackChans, k)
	}
	for k := range n.completedAck {
		delete(n.completedAck, k)
	}
	for k := range n.quorumReached {
		delete(n.quorumReached, k)
	}
	n.ackChansMu.Unlock()

	n.viewChangeMu.Lock()
	n.viewChangeMsgs = make(map[uint64]map[uint64]*pbftproto.ViewChangeMsg)
	n.viewChangeMu.Unlock()

	n.executedMu.Lock()
	n.Executed = make(map[string]bool)
	n.executedMu.Unlock()

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		getBool := func(key string) (bool, bool) {
			vals := md.Get(key)
			if len(vals) == 0 {
				return false, false
			}
			v := strings.ToLower(strings.TrimSpace(vals[0]))
			if v == "1" || v == "true" || v == "yes" {
				return true, true
			}
			if v == "0" || v == "false" || v == "no" {
				return false, true
			}
			return false, false
		}
		getIDs := func(key string) map[uint64]bool {
			out := make(map[uint64]bool)
			vals := md.Get(key)
			if len(vals) == 0 {
				return out
			}
			raw := strings.TrimSpace(vals[0])
			if raw == "" {
				return out
			}
			parts := strings.Split(raw, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if len(p) > 1 && (p[0] == 'n' || p[0] == 'N') {
					p = p[1:]
				}
				id, err := strconv.ParseUint(p, 10, 64)
				if err == nil {
					out[id] = true
				}
			}
			return out
		}

		if v, ok := getBool("disabled"); ok {
			n.Disabled = v
		}
		if v, ok := getBool("crash"); ok {
			n.Crash = v
		}
		if v, ok := getBool("signature-attack"); ok {
			n.SignatureAttack = v
		}
		if v, ok := getBool("time-attack"); ok {
			n.TimeAttack = v
		}
		if v, ok := getBool("in-dark"); ok {
			n.InDarkAttack = v
		}
		if v, ok := getBool("equivocation"); ok {
			n.Equivocation = v
		}

		n.DarkPeers = getIDs("dark-peers")
		n.EquivocatePeers = getIDs("equiv-peers")

		if vals := md.Get("timer-ms"); len(vals) > 0 {
			if ms, err := strconv.Atoi(strings.TrimSpace(vals[0])); err == nil && ms > 0 {
				n.timerDuration = time.Duration(ms) * time.Millisecond
			}
		}

		log.Printf("[node %d] ResetState: flags updated disabled=%v crash=%v sign=%v time=%v inDark=%v darkPeers=%v equiv=%v equivPeers=%v",
			n.ID, n.Disabled, n.Crash, n.SignatureAttack, n.TimeAttack, n.InDarkAttack, n.DarkPeers, n.Equivocation, n.EquivocatePeers)
	} else {
		log.Printf("[node %d] ResetState: no metadata; state reset only", n.ID)
	}

	return &pbftproto.ResetReply{Ok: true}, nil
}

func (ps *PrimaryServer) HandleClientRequest(ctx context.Context, req *pbftproto.ClientRequest) (*pbftproto.ClientReply, error) {
	n := ps.Node

	if req == nil || req.From == "" {
		return &pbftproto.ClientReply{Success: false, Message: "invalid request", View: n.View}, nil
	}

	if strings.HasPrefix(strings.ToUpper(req.From), "__ADMIN__") || strings.EqualFold(req.From, "ADMIN") {
		cmd := strings.ToUpper(strings.TrimSpace(req.To))
		switch cmd {
		case "PRINTLOG":
			return &pbftproto.ClientReply{Success: true, Message: n.buildLogString(), View: n.View}, nil
		case "PRINTDB":
			return &pbftproto.ClientReply{Success: true, Message: n.buildDBString(), View: n.View}, nil
		case "PRINTSTATUS":
			seq := uint64(0)
			if s := strings.TrimSpace(req.Timestamp); s != "" {
				if v, err := strconv.ParseUint(s, 10, 64); err == nil {
					seq = v
				}
			}
			lbl := n.statusLabelFor(seq)
			return &pbftproto.ClientReply{Success: true, Message: fmt.Sprintf("seq=%d status=%s", seq, lbl), View: n.View}, nil
		case "PRINTVIEW":
			return &pbftproto.ClientReply{Success: true, Message: n.buildViewString(), View: n.View}, nil
		default:
			return &pbftproto.ClientReply{Success: false, Message: "unknown admin command", View: n.View}, nil
		}
	}

	leaderID := n.primaryForView(n.View)
	if n.ID != leaderID {
		n.mu.Lock()
		leaderCli := n.PrimaryClients[leaderID]
		n.mu.Unlock()
		if leaderCli == nil {
			return nil, fmt.Errorf("node %d not leader (leader=%d), and no PrimaryClient", n.ID, leaderID)
		}
		return leaderCli.HandleClientRequest(ctx, req)
	}

	digest := crypto.ComputeRequestDigest(&pbftproto.ClientRequest{From: req.From, To: req.To, Amount: req.Amount, Timestamp: req.Timestamp})
	if err := n.PrimaryBroadcastPrePrepare(ctx, req); err != nil {
		return nil, fmt.Errorf("preprepare failed: %v", err)
	}

	// Wait until executed
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for execution")
		case <-ticker.C:
			var seq uint64
			var status string
			n.logMu.RLock()
			for s, e := range n.Log {
				if e == nil || e.Digest == nil {
					continue
				}
				if crypto.EqualBytes(e.Digest, digest) {
					seq = s
					status = e.Status
					break
				}
			}
			n.logMu.RUnlock()
			if seq == 0 {
				continue
			}
			if status == "Execute" {
				return &pbftproto.ClientReply{Success: true, Message: "ok", View: n.View, Seq: seq}, nil
			}
		}
	}
}

func (n *Node) sendClientReplyFor(seq uint64, success bool, msg string) {
	n.logMu.RLock()
	e, ok := n.Log[seq]
	n.logMu.RUnlock()
	if !ok || e.Payload == nil || e.Payload.ClientAddr == "" {
		return
	}

	tx := e.Payload
	addr := tx.ClientAddr

	r := &pbftproto.ClientReply{
		Success:   success,
		Message:   msg,
		View:      e.View,
		Seq:       e.Seq,
		Balance:   0,
		From:      tx.From,
		Timestamp: tx.Timestamp,
		ReplicaId: n.ID,
	}

	if tx.From == tx.To && tx.Amount == 0 {
		n.mu.Lock()
		r.Balance = n.DB[tx.From]
		n.mu.Unlock()
		if success {
			r.Message = fmt.Sprintf("balance=%d", r.Balance)
		}
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		if err != nil {
			log.Printf("[node %d] DeliverClientReply dial %s failed: %v", n.ID, addr, err)
			return
		}
		defer conn.Close()

		cli := pbftproto.NewClientServiceClient(conn)
		defer cancel()

		if _, err := cli.DeliverClientReply(ctx, r); err != nil {
			log.Printf("[node %d] DeliverClientReply error to %s: %v", n.ID, addr, err)
		}
	}()
}
