package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	pbftproto "pbft/proto"
	crypto "pbft/utils"
	"time"
)

type ReplicaServer struct {
	Node *Node
	pbftproto.UnimplementedReplicaServiceServer
}

func (rs *ReplicaServer) HandlePrePrepare(ctx context.Context, msg *pbftproto.PrePrepareMsg) (*pbftproto.AckReceipt, error) {
	n := rs.Node
	if n.Disabled || n.Crash {
		return &pbftproto.AckReceipt{Ok: false, Message: "node disabled"}, nil
	}

	if !n.verifyPrePrepareSig(msg.PrimaryId, msg.View, msg.Seq, msg.Digest, msg.Signature) {
		return &pbftproto.AckReceipt{Ok: false, Message: "bad primary signature"}, nil
	}

	if msg.Seq <= n.LowWM || msg.Seq > n.HighWM {
		return &pbftproto.AckReceipt{Ok: false, Message: "seq outside watermarks"}, nil
	}

	if e, ok := n.Log[msg.Seq]; ok {
		if e.View != msg.View || !crypto.EqualBytes(e.Digest, msg.Digest) {
			return &pbftproto.AckReceipt{Ok: false, Message: "conflicting preprepare"}, nil
		}
	} else {
		cand := &crypto.Log{
			Status:  "PrePrepare",
			View:    msg.View,
			Seq:     msg.Seq,
			Digest:  msg.Digest,
			Primary: msg.PrimaryId,
			Payload: msg.Request,
		}
		n.logMu.Lock()
		if _, ok2 := n.Log[msg.Seq]; !ok2 {
			n.Log[msg.Seq] = cand
		}
		n.logMu.Unlock()
	}
	if msg.View > n.View {
		n.View = msg.View
	}
	if msg.Seq > n.Seq {
		n.Seq = msg.Seq
	}

	entry := &crypto.Log{
		Status:  "PrePrepare",
		View:    msg.View,
		Seq:     msg.Seq,
		Digest:  msg.Digest,
		Primary: msg.PrimaryId,
		Payload: msg.Request,
	}

	n.logMu.Lock()
	n.Log[msg.Seq] = entry
	n.logMu.Unlock()

	n.PrintLogSnapshot("PREPREPARE (replica)", msg.Seq)
	if n.Crash {
		n.PrintLogSnapshot("CRASH-BACKUP (suppress PREPREPARE)", msg.Seq)
		return &pbftproto.AckReceipt{Ok: true, Message: "pre-prepare suppressed (crash)"}, nil
	}

	n.View = msg.View
	n.Seq = msg.Seq

	if n.ID != msg.PrimaryId && msg.Request != nil {
		if !(msg.Request.From == msg.Request.To && msg.Request.Amount == 0) {
			n.timerMu.Lock()
			active := n.timerActive
			cur := n.timerForSeq
			n.timerMu.Unlock()
			if active {
				if msg.Seq < cur {
					n.retargetTimerToSeq(msg.Seq)
				}
			} else {
				n.startRequestTimer(msg.Seq)
			}
		}
	}

	ackSig := n.signMaybeCorrupt(msg.View, msg.Seq, msg.Digest)

	ack := &pbftproto.PrePrepareAck{
		View:      msg.View,
		Seq:       msg.Seq,
		Digest:    msg.Digest,
		ReplicaId: n.ID,
		Signature: ackSig,
	}

	if n.InDarkAttack && n.isDark(msg.PrimaryId) {
		log.Printf("[node %d] IN-DARK: dropping PrePrepareAck to primary %d (seq=%d)", n.ID, msg.PrimaryId, msg.Seq)
		return &pbftproto.AckReceipt{Ok: true, Message: "silent (in-dark)"}, nil
	}
	if err := n.waitAndSendPrePrepareAck(ctx, ack); err != nil {
		fmt.Println("PrePrepare :: failed to send ack to primary", err)
		return &pbftproto.AckReceipt{Ok: false, Message: "failed to send ack to primary"}, nil
	}

	return &pbftproto.AckReceipt{Ok: true, Message: "accepted"}, nil
}

func (rs *ReplicaServer) HandlePrepare(ctx context.Context, msg *pbftproto.PrepareMsg) (*pbftproto.AckReceipt, error) {
	n := rs.Node
	if n.Disabled || n.Crash {
		return &pbftproto.AckReceipt{Ok: false, Message: "node disabled"}, nil
	}

	if !n.verifyPrePrepareSig(msg.PrimaryId, msg.View, msg.Seq, msg.Digest, msg.Signature) {
		return &pbftproto.AckReceipt{Ok: false, Message: "bad primary signature"}, nil
	}

	if msg.Seq <= n.LowWM || msg.Seq > n.HighWM {
		return &pbftproto.AckReceipt{Ok: false, Message: "seq outside watermarks"}, nil
	}

	entry, ok := n.Log[msg.Seq]
	if !ok || entry.View != msg.View || !crypto.EqualBytes(entry.Digest, msg.Digest) {
		return &pbftproto.AckReceipt{Ok: false, Message: "unknown or mismatched preprepare"}, nil
	}

	if len(msg.QuorumIds) > 0 && !crypto.ContainsUint64(msg.QuorumIds, n.ID) {
		return &pbftproto.AckReceipt{Ok: false, Message: "not in preprepare quorum"}, nil
	}
	n.logMu.Lock()
	if entry.Status == "" || entry.Status == "PrePrepare" {
		crypto.BumpStatus(entry, "Prepare")
	}
	n.logMu.Unlock()
	n.PrintLogSnapshot("PREPARE (replica)", msg.Seq)

	if n.Crash {
		n.PrintLogSnapshot("CRASH-BACKUP (suppress PREPARE)", msg.Seq)
		return &pbftproto.AckReceipt{Ok: true, Message: "prepare suppressed (crash)"}, nil
	}

	ackSig := n.signMaybeCorrupt(msg.View, msg.Seq, msg.Digest)

	ack := &pbftproto.PrepareAck{
		View:      msg.View,
		Seq:       msg.Seq,
		Digest:    msg.Digest,
		ReplicaId: n.ID,
		Signature: ackSig,
	}

	if n.InDarkAttack && n.isDark(msg.PrimaryId) {
		log.Printf("[node %d] IN-DARK: dropping PrepareAck to primary %d (seq=%d)", n.ID, msg.PrimaryId, msg.Seq)
		return &pbftproto.AckReceipt{Ok: true, Message: "silent (in-dark)"}, nil
	}
	err := n.waitAndSendPrepareAck(ctx, ack)
	if err != nil {
		return &pbftproto.AckReceipt{Ok: false, Message: "failed to send PrepareAck"}, nil
	}
	return &pbftproto.AckReceipt{Ok: true, Message: "prepare accepted"}, nil
}

func (rs *ReplicaServer) HandleCommit(ctx context.Context, msg *pbftproto.CommitMsg) (*pbftproto.AckReceipt, error) {
	n := rs.Node
	if n.Disabled || n.Crash {
		return &pbftproto.AckReceipt{Ok: false, Message: "node disabled"}, nil
	}

	if !n.verifyPrePrepareSig(msg.PrimaryId, msg.View, msg.Seq, msg.Digest, msg.Signature) {
		return &pbftproto.AckReceipt{Ok: false, Message: "bad primary signature"}, nil
	}

	if msg.Seq <= n.LowWM || msg.Seq > n.HighWM {
		return &pbftproto.AckReceipt{Ok: false, Message: "seq outside watermarks"}, nil
	}

	entry, ok := n.Log[msg.Seq]
	if !ok || entry.View != msg.View || !crypto.EqualBytes(entry.Digest, msg.Digest) {
		return &pbftproto.AckReceipt{Ok: false, Message: "unknown or mismatched entry"}, nil
	}

	if len(msg.QuorumIds) > 0 && !crypto.ContainsUint64(msg.QuorumIds, n.ID) {
		return &pbftproto.AckReceipt{Ok: false, Message: "not in prepare quorum"}, nil
	}

	n.logMu.Lock()
	if entry.Status == "Prepare" {
		crypto.BumpStatus(entry, "Commit")
	}
	n.logMu.Unlock()
	n.PrintLogSnapshot("COMMIT (replica)", msg.Seq)
	if n.Crash {
		n.PrintLogSnapshot("CRASH-BACKUP (suppress COMMIT)", msg.Seq)
		return &pbftproto.AckReceipt{Ok: true, Message: "commit suppressed (crash)"}, nil
	}

	n.executeTxn()
	n.writeDBJSON()
	n.retargetTimerToMinPending()

	n.PrintLogSnapshot("EXECUTE (replica)", msg.Seq)
	n.logMu.RLock()
	e := n.Log[msg.Seq]
	seq := msg.Seq
	n.logMu.RUnlock()

	if e != nil {
		success := (e.Result == "" || e.Result == "ok")
		msg := e.Result
		if msg == "" && success {
			msg = "ok"
		}
		n.sendClientReplyFor(seq, success, msg)
	}

	ackSig := n.signMaybeCorrupt(msg.View, msg.Seq, msg.Digest)
	ack := &pbftproto.CommitAck{
		View:      msg.View,
		Seq:       msg.Seq,
		Digest:    msg.Digest,
		ReplicaId: n.ID,
		Signature: ackSig,
	}

	if n.InDarkAttack && n.isDark(msg.PrimaryId) {
		log.Printf("[node %d] IN-DARK: dropping CommitAck to primary %d (seq=%d)", n.ID, msg.PrimaryId, msg.Seq)
		return &pbftproto.AckReceipt{Ok: true, Message: "silent (in-dark)"}, nil
	}
	n.retargetTimerToMinPending()

	err := n.waitAndSendCommitAck(ctx, ack)
	if err != nil {
		return &pbftproto.AckReceipt{Ok: false, Message: "failed to send CommitAck"}, nil
	}
	return &pbftproto.AckReceipt{Ok: true, Message: "commit accepted"}, nil
}

func (ps *PrimaryServer) HandleViewChange(ctx context.Context, msg *pbftproto.ViewChangeMsg) (*pbftproto.ViewChangeAck, error) {
	n := ps.Node

	if n.Disabled {
		return &pbftproto.ViewChangeAck{Ok: false, Message: "node disabled"}, nil
	}

	if msg.NewView <= n.View {
		return &pbftproto.ViewChangeAck{Ok: false, Message: "stale view-change"}, nil
	}

	if !n.VerifyViewChangeSignature(msg) {
		return &pbftproto.ViewChangeAck{Ok: false, Message: "invalid signature"}, nil
	}

	n.viewChangeMu.Lock()
	mset, ok := n.viewChangeMsgs[msg.NewView]
	if !ok {
		mset = make(map[uint64]*pbftproto.ViewChangeMsg)
		n.viewChangeMsgs[msg.NewView] = mset
	}
	if _, exists := mset[msg.ReplicaId]; !exists {
		mset[msg.ReplicaId] = msg
	}
	count := len(mset)
	n.viewChangeMu.Unlock()

	const f = 2
	if n.primaryForView(msg.NewView) != n.ID {
		if count >= f+1 {
			n.mu.Lock()
			shouldStart := (msg.NewView > n.View) && (!n.InViewChange || msg.NewView > n.PendingView)
			n.mu.Unlock()
			if shouldStart {
				n.StartViewChange(msg.NewView)
			}
		}
		return &pbftproto.ViewChangeAck{Ok: true, Message: "view-change recorded"}, nil
	}

	if n.primaryForView(msg.NewView) == n.ID && n.Crash {
		return &pbftproto.ViewChangeAck{Ok: true, Message: "view-change recorded (crash primary)"}, nil
	}
	if count >= 2*f+1 {
		go func(view uint64) {
			nv, err := n.BuildNewViewMsg(view)
			if err != nil {
				log.Printf("[node %d] BuildNewViewMsg failed for v=%d: %v", n.ID, view, err)
				return
			}
			n.BroadcastNewView(nv)
		}(msg.NewView)
	}
	return &pbftproto.ViewChangeAck{Ok: true, Message: "view-change accepted"}, nil
}

func (n *Node) VerifyViewChangeSignature(msg *pbftproto.ViewChangeMsg) bool {
	h := crypto.NewHasher()
	h.WriteUint64(msg.NewView)
	if msg.Checkpoint != nil {
		h.WriteUint64(msg.Checkpoint.Seq)
	}
	for _, e := range msg.Entries {
		h.WriteUint64(e.Seq)
		h.WriteUint64(e.View)
		h.WriteBytes(e.Digest)
	}
	digest := h.Sum()

	pub, ok := n.PubKeys[msg.ReplicaId]
	if !ok {
		return false
	}
	return ed25519.Verify(pub, digest, msg.Signature)
}

func (n *Node) waitAndSendPrePrepareAck(_ context.Context, ack *pbftproto.PrePrepareAck) error {
	deadline := time.After(3 * time.Second)
	for {
		n.mu.Lock()
		pc := n.PrimaryClients[n.primaryForView(n.View)]
		n.mu.Unlock()
		if pc != nil {
			cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := pc.SendPrePrepareAck(cctx, ack)
			return err
		}
		select {
		case <-deadline:
			return fmt.Errorf("primary client not ready")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (n *Node) waitAndSendPrepareAck(_ context.Context, ack *pbftproto.PrepareAck) error {
	deadline := time.After(3 * time.Second)
	for {
		n.mu.Lock()
		pc := n.PrimaryClients[n.primaryForView(n.View)]
		n.mu.Unlock()
		if pc != nil {
			cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := pc.SendPrepareAck(cctx, ack)
			return err
		}
		select {
		case <-deadline:
			return fmt.Errorf("primary client not ready")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (n *Node) waitAndSendCommitAck(_ context.Context, ack *pbftproto.CommitAck) error {
	deadline := time.After(3 * time.Second)
	for {
		n.mu.Lock()
		pc := n.PrimaryClients[n.primaryForView(n.View)]
		n.mu.Unlock()
		if pc != nil {
			cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := pc.SendCommitAck(cctx, ack)
			return err
		}
		select {
		case <-deadline:
			return fmt.Errorf("primary client not ready")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (n *Node) BuildViewChangeMsg(newView uint64) *pbftproto.ViewChangeMsg {
	cp := &pbftproto.Checkpoint{
		Seq:         0,
		StateDigest: nil,
	}

	n.logMu.RLock()
	entries := make([]*pbftproto.ViewChangeEntry, 0)
	for _, le := range n.Log {
		if le == nil {
			continue
		}
		if le.Seq <= cp.Seq {
			continue
		}
		e := &pbftproto.ViewChangeEntry{
			Seq:    le.Seq,
			View:   le.View,
			Digest: le.Digest,
			Status: le.Status,
		}
		if len(le.QuorumPrepare) > 0 {
			e.QuorumPrepare = append([]uint64(nil), le.QuorumPrepare...)
		}
		entries = append(entries, e)
	}
	n.logMu.RUnlock()

	h := crypto.NewHasher()
	h.WriteUint64(newView)
	h.WriteUint64(cp.Seq)
	for _, e := range entries {
		h.WriteUint64(e.Seq)
		h.WriteUint64(e.View)
		h.WriteBytes(e.Digest)
	}
	digest := h.Sum()
	sig := ed25519.Sign(n.PrivKey, digest)

	return &pbftproto.ViewChangeMsg{
		NewView:    newView,
		ReplicaId:  n.ID,
		Checkpoint: cp,
		Entries:    entries,
		Signature:  sig,
	}
}

func (n *Node) StartViewChange(newView uint64) {
	n.mu.Lock()
	if newView <= n.View || (n.InViewChange && newView <= n.PendingView) {
		n.mu.Unlock()
		return
	}
	n.PendingView = newView
	n.InViewChange = true
	n.mu.Unlock()

	targetPrimary := n.primaryForView(newView)
	vc := n.BuildViewChangeMsg(newView)

	if targetPrimary == n.ID {
		n.viewChangeMu.Lock()
		mset, ok := n.viewChangeMsgs[newView]
		if !ok {
			mset = make(map[uint64]*pbftproto.ViewChangeMsg)
			n.viewChangeMsgs[newView] = mset
		}
		mset[n.ID] = vc
		n.viewChangeMu.Unlock()
		return
	}

	n.mu.Lock()
	cli := n.PrimaryClients[targetPrimary]
	n.mu.Unlock()
	if cli == nil {
		log.Printf("[node %d] cannot start view-change to v=%d: no primary client for %d",
			n.ID, newView, targetPrimary)
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ack, err := cli.HandleViewChange(ctx, vc)
		if err != nil || !ack.Ok {
			log.Printf("[node %d] view-change to v=%d -> primary %d failed: %v, %+v",
				n.ID, newView, targetPrimary, err, ack)
			return
		}
	}()
}
