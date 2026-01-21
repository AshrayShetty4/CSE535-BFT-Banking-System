package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	pbftproto "pbft/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	numNodes       = 7
	numLogicalClis = 10
	f              = 2
	quorumSize     = 2*f + 1
	defaultTimeout = 7 * time.Second
)

type NodeClient struct {
	ID   uint64
	Addr string
	Conn *grpc.ClientConn
	Cli  pbftproto.PrimaryServiceClient
}

type LogicalClient struct {
	ID            int
	currentView   uint64
	currentLeader uint64

	nodes map[uint64]*NodeClient

	// Per-request timeout
	timeout time.Duration
	mu      sync.Mutex
}

// Parsed transaction from CSV
type Tx struct {
	SetID int

	From   string
	To     string
	Amount uint64

	Raw        string
	ClientAddr string
}

type pendingKey struct {
	From      string
	Timestamp string
}

type pendingResult struct {
	mu      sync.Mutex
	replies []*pbftproto.ClientReply
	done    chan struct{}
	decided bool
	final   *pbftproto.ClientReply
}

type ClientReplyServer struct {
	pbftproto.UnimplementedClientServiceServer

	mu      sync.Mutex
	pending map[pendingKey]*pendingResult

	f int
}

type TestSet struct {
	ID        int
	Txns      []Tx
	Live      []uint64
	Byzantine []uint64
	Attacks   []string
}

func parseNodeList(s string) []uint64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "[]" {
		return nil
	}

	if strings.HasPrefix(s, "[") {
		s = strings.TrimPrefix(s, "[")
	}
	if strings.HasSuffix(s, "]") {
		s = strings.TrimSuffix(s, "]")
	}

	parts := strings.Split(s, ",")
	out := make([]uint64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if len(p) > 1 && (p[0] == 'n' || p[0] == 'N') {
			p = p[1:]
		}
		id, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			log.Printf("parseNodeList: skip token %q: %v", p, err)
			continue
		}
		out = append(out, id)
	}
	return out
}

func parseAttacks(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	trimmed := strings.Trim(s, "[]")
	parts := strings.Split(trimmed, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseTxnCell(cell string) (Tx, error) {
	cell = strings.TrimSpace(cell)
	if cell == "" {
		return Tx{}, fmt.Errorf("empty txn cell")
	}
	if !strings.HasPrefix(cell, "(") || !strings.HasSuffix(cell, ")") {
		return Tx{}, fmt.Errorf("bad format: %s", cell)
	}

	inner := strings.TrimSpace(cell[1 : len(cell)-1])
	if inner == "" {
		return Tx{}, fmt.Errorf("empty inner: %s", cell)
	}

	parts := strings.Split(inner, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	if len(parts) == 1 {
		from := parts[0]
		if from == "" {
			return Tx{}, fmt.Errorf("empty sender in %s", cell)
		}
		return Tx{
			From:   from,
			To:     from,
			Amount: 0,
			Raw:    cell,
		}, nil
	}

	if len(parts) != 3 {
		return Tx{}, fmt.Errorf("bad txn parts in %s", cell)
	}

	from := parts[0]
	to := parts[1]
	if from == "" || to == "" {
		return Tx{}, fmt.Errorf("empty from/to in %s", cell)
	}

	amt, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return Tx{}, fmt.Errorf("bad amount in %s: %v", cell, err)
	}

	return Tx{
		From:   from,
		To:     to,
		Amount: amt,
		Raw:    cell,
	}, nil
}

func loadTestSets(path string) ([]TestSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true

	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty csv")
	}

	setsByID := make(map[int]*TestSet)
	var order []int
	var currentSet *TestSet

	for i := 1; i < len(rows); i++ {
		record := rows[i]
		if len(record) < 5 {
			continue
		}

		setStr := strings.TrimSpace(record[0])
		txnCell := strings.TrimSpace(record[1])
		liveCell := strings.TrimSpace(record[2])
		byzCell := strings.TrimSpace(record[3])
		attackCell := strings.TrimSpace(record[4])

		if setStr != "" {
			setID, err := strconv.Atoi(setStr)
			if err != nil {
				log.Printf("skip row %d: bad set id %q: %v", i+1, setStr, err)
				currentSet = nil
				continue
			}

			ts, ok := setsByID[setID]
			if !ok {
				ts = &TestSet{ID: setID}
				setsByID[setID] = ts
				order = append(order, setID)
			}
			currentSet = ts

			if liveCell != "" && len(ts.Live) == 0 {
				ts.Live = parseNodeList(liveCell)
			}
			if byzCell != "" && len(ts.Byzantine) == 0 {
				ts.Byzantine = parseNodeList(byzCell)
			}
			if attackCell != "" && len(ts.Attacks) == 0 {
				ts.Attacks = parseAttacks(attackCell)
			}
		}

		if currentSet == nil {
			continue
		}

		if txnCell == "" {
			continue
		}

		tx, err := parseTxnCell(txnCell)
		if err != nil {
			log.Printf("skip bad txn %q on row %d: %v", txnCell, i+1, err)
			continue
		}
		currentSet.Txns = append(currentSet.Txns, tx)

	}

	result := make([]TestSet, 0, len(order))
	for _, id := range order {
		ts := setsByID[id]
		if len(ts.Live) == 0 {
			ts.Live = []uint64{1, 2, 3, 4, 5, 6, 7}
		}
		result = append(result, *ts)
	}
	return result, nil
}

func parseNodesFlag(s string) (map[uint64]string, error) {
	res := make(map[uint64]string)
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("bad -nodes entry %q", p)
		}
		id, err := strconv.ParseUint(strings.TrimSpace(kv[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad node id in %q: %v", p, err)
		}
		res[id] = strings.TrimSpace(kv[1])
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("no nodes parsed from %q", s)
	}
	return res, nil
}

func dialNodes(nodeAddrs map[uint64]string) (map[uint64]*NodeClient, error) {
	out := make(map[uint64]*NodeClient)
	for id, addr := range nodeAddrs {
		conn, err := grpc.Dial(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
			grpc.WithTimeout(3*time.Second),
		)
		if err != nil {
			return nil, fmt.Errorf("dial node %d @ %s: %w", id, addr, err)
		}
		out[id] = &NodeClient{
			ID:   id,
			Addr: addr,
			Conn: conn,
			Cli:  pbftproto.NewPrimaryServiceClient(conn),
		}
	}
	return out, nil
}

func newLogicalClients(nodes map[uint64]*NodeClient, timeout time.Duration) []*LogicalClient {
	clients := make([]*LogicalClient, 0, numLogicalClis)
	for i := 0; i < numLogicalClis; i++ {
		lc := &LogicalClient{
			ID:            i + 1,
			currentView:   0,
			currentLeader: 1,
			nodes:         nodes,
			timeout:       timeout,
		}
		clients = append(clients, lc)
	}
	return clients
}

func pickClientForSender(clients []*LogicalClient, from string) *LogicalClient {
	if from == "" {
		return clients[0]
	}
	c := from[0]
	idx := int(c-'A') % len(clients)
	if idx < 0 {
		idx = 0
	}
	return clients[idx]
}

func viewToLeader(view uint64) uint64 {
	return (view % numNodes) + 1
}

func (lc *LogicalClient) SendRequest(ctx context.Context, req *pbftproto.ClientRequest, liveNodes []uint64) (*pbftproto.ClientReply, error) {
	isTerminalFailure := func(rep *pbftproto.ClientReply) bool {
		if rep == nil {
			return false
		}
		if !rep.Success && strings.Contains(strings.ToLower(rep.Message), "insufficient") {
			return true
		}
		return false
	}

	liveSet := make(map[uint64]struct{})
	for _, id := range liveNodes {
		liveSet[id] = struct{}{}
	}
	if len(liveSet) == 0 {
		for id := range lc.nodes {
			liveSet[id] = struct{}{}
		}
	}

	for {
		isReadOnly := (req.From == req.To && req.Amount == 0)
		if isReadOnly {
			rep, ok := lc.broadcastAndWaitQuorum(req, liveSet)
			if ok {
				if rep.View != 0 && rep.View != lc.currentView {
					lc.currentView = rep.View
					lc.currentLeader = viewToLeader(rep.View)
				}
				return rep, nil
			}
		}
		leaderID := lc.currentLeader
		if _, ok := liveSet[leaderID]; !ok {
			leaderID = 0
			for id := range liveSet {
				if leaderID == 0 || id < leaderID {
					leaderID = id
				}
			}
		}
		if leaderID != 0 {
			if rep, err := lc.callNodeOnce(leaderID, req); err == nil && rep != nil {
				fmt.Println("Leader called successfully")
				if rep.View != 0 && rep.View != lc.currentView {
					lc.currentView = rep.View
					lc.currentLeader = viewToLeader(rep.View)
				}
				if rep.Success || isTerminalFailure(rep) {
					return rep, nil
				}
			}
		}
		rep, ok := lc.broadcastAndWaitQuorum(req, liveSet)
		if ok {
			if rep.View != 0 && rep.View != lc.currentView {
				lc.currentView = rep.View
				lc.currentLeader = viewToLeader(rep.View)
			}
			return rep, nil
		}
		log.Printf("[client %d] retrying request %s -> %s amt=%d (no quorum)",
			lc.ID, req.From, req.To, req.Amount)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
}

func (lc *LogicalClient) callNodeOnce(nodeID uint64, req *pbftproto.ClientRequest) (*pbftproto.ClientReply, error) {
	nc, ok := lc.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("unknown node %d", nodeID)
	}
	fmt.Println("Calling node", nc.Addr)
	ctx, cancel := context.WithTimeout(context.Background(), lc.timeout)
	defer cancel()
	rep, err := nc.Cli.HandleClientRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep, nil
}

func (lc *LogicalClient) broadcastAndWaitQuorum(req *pbftproto.ClientRequest, liveSet map[uint64]struct{}) (*pbftproto.ClientReply, bool) {
	type repWrapper struct {
		from uint64
		rep  *pbftproto.ClientReply
	}

	ctx, cancel := context.WithTimeout(context.Background(), lc.timeout)
	defer cancel()

	ch := make(chan repWrapper, len(lc.nodes))
	var wg sync.WaitGroup

	for id, nc := range lc.nodes {
		if _, ok := liveSet[id]; !ok {
			continue
		}
		wg.Add(1)
		go func(id uint64, cli pbftproto.PrimaryServiceClient) {
			defer wg.Done()
			cctx, ccancel := context.WithTimeout(ctx, lc.timeout)
			defer ccancel()
			rep, err := cli.HandleClientRequest(cctx, req)
			if err != nil || rep == nil {
				return
			}
			select {
			case ch <- repWrapper{from: id, rep: rep}:
			case <-ctx.Done():
			}
		}(id, nc.Cli)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	type key struct {
		success bool
		msg     string
		view    uint64
		seq     uint64
		balance uint64
	}

	counts := make(map[key]int)
	samples := make(map[key]*pbftproto.ClientReply)

	for {
		select {
		case <-ctx.Done():
			return nil, false
		case w, ok := <-ch:
			if !ok {
				return nil, false
			}
			if w.rep == nil {
				continue
			}
			k := key{
				success: w.rep.Success,
				msg:     w.rep.Message,
				view:    w.rep.View,
				seq:     w.rep.Seq,
				balance: w.rep.Balance,
			}
			counts[k]++
			if samples[k] == nil {
				samples[k] = w.rep
			}
			if counts[k] >= quorumSize {
				return samples[k], true
			}
		}
	}
}

func configureAndResetNodes(nodes map[uint64]*NodeClient, ts TestSet) {
	live := make(map[uint64]bool)
	for _, id := range ts.Live {
		live[id] = true
	}
	byz := make(map[uint64]bool)
	for _, id := range ts.Byzantine {
		byz[id] = true
	}

	var (
		attackSign   bool
		attackCrash  bool
		attackTime   bool
		attackDark   bool
		attackEquiv  bool
		darkTargets  []uint64
		equivTargets []uint64
	)

	fmt.Printf("Attacks are %+v\n", ts.Attacks)
	for _, a := range ts.Attacks {
		al := strings.ToLower(strings.TrimSpace(a))
		switch {
		case al == "sign":
			attackSign = true
		case al == "crash":
			attackCrash = true
		case al == "time":
			attackTime = true
		case strings.HasPrefix(al, "dark(") && strings.HasSuffix(al, ")"):
			attackDark = true
			inner := strings.TrimSpace(al[len("dark(") : len(al)-1])
			for _, p := range strings.Split(inner, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if len(p) > 1 && (p[0] == 'n' || p[0] == 'N') {
					p = p[1:]
				}
				if id, err := strconv.ParseUint(p, 10, 64); err == nil {
					darkTargets = append(darkTargets, id)
				}
			}
		case strings.HasPrefix(al, "equivocation(") && strings.HasSuffix(al, ")"):
			attackEquiv = true
			inner := strings.TrimSpace(al[len("equivocation(") : len(al)-1])
			for _, p := range strings.Split(inner, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if len(p) > 1 && (p[0] == 'n' || p[0] == 'N') {
					p = p[1:]
				}
				if id, err := strconv.ParseUint(p, 10, 64); err == nil {
					equivTargets = append(equivTargets, id)
				}
			}
		}
	}

	var wg sync.WaitGroup
	for id, nc := range nodes {
		id := id
		cli := nc.Cli
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Base flags
			disabled := !live[id]
			isByz := byz[id]

			timerMS := 2000
			if len(ts.Attacks) == 0 {
				timerMS = 8000
			}

			pairs := []string{
				"disabled", fmt.Sprintf("%t", disabled),
				"crash", fmt.Sprintf("%t", isByz && attackCrash),
				"signature-attack", fmt.Sprintf("%t", isByz && attackSign),
				"time-attack", fmt.Sprintf("%t", isByz && attackTime),
				"in-dark", fmt.Sprintf("%t", isByz && attackDark),
				"equivocation", fmt.Sprintf("%t", isByz && attackEquiv),
				"timer-ms", fmt.Sprintf("%d", timerMS),
			}

			if len(ts.Attacks) == 0 {
				pairs = append(pairs, "timer-ms", "8000")
			} else {
				pairs = append(pairs, "timer-ms", "2000")
			}
			if isByz && attackDark && len(darkTargets) > 0 {
				var b strings.Builder
				for i, t := range darkTargets {
					if i > 0 {
						b.WriteByte(',')
					}
					b.WriteString(fmt.Sprintf("%d", t))
				}
				pairs = append(pairs, "dark-peers", b.String())
			} else {
				pairs = append(pairs, "dark-peers", "")
			}
			if isByz && attackEquiv && len(equivTargets) > 0 {
				var b strings.Builder
				for i, t := range equivTargets {
					if i > 0 {
						b.WriteByte(',')
					}
					b.WriteString(fmt.Sprintf("%d", t))
				}
				pairs = append(pairs, "equiv-peers", b.String())
			} else {
				pairs = append(pairs, "equiv-peers", "")
			}

			md := metadata.Pairs(pairs...)
			ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), md), 3*time.Second)
			defer cancel()
			_, err := cli.ResetState(ctx, &pbftproto.ResetRequest{})
			if err != nil {
				log.Printf("[client] Configure+Reset to node %d failed: %v", id, err)
			} else {
				log.Printf("[client] Configure+Reset ok on node %d (disabled=%v byz=%v)", id, disabled, isByz)
			}
		}()
	}
	wg.Wait()
}

func (s *ClientReplyServer) DeliverClientReply(ctx context.Context, r *pbftproto.ClientReply) (*pbftproto.ResetRequest, error) {
	key := pendingKey{From: r.From, Timestamp: r.Timestamp}

	s.mu.Lock()
	pr, ok := s.pending[key]
	s.mu.Unlock()

	if !ok {
		return &pbftproto.ResetRequest{}, nil
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	if pr.decided {
		return &pbftproto.ResetRequest{}, nil
	}

	for _, ex := range pr.replies {
		if ex.ReplicaId == r.ReplicaId {
			return &pbftproto.ResetRequest{}, nil
		}
	}

	pr.replies = append(pr.replies, r)

	needed := s.f + 1
	for i := range pr.replies {
		base := pr.replies[i]
		cnt := 0
		for j := range pr.replies {
			if pr.replies[j].Success == base.Success &&
				pr.replies[j].Message == base.Message &&
				pr.replies[j].Seq == base.Seq {
				cnt++
			}
		}
		if cnt >= needed {
			pr.decided = true
			pr.final = base
			close(pr.done)
			break
		}
	}

	return &pbftproto.ResetRequest{}, nil
}

// ---------- main ----------

func main() {

	csvPath := flag.String("csv", "CSE535-F25-Project-2-Testcases.csv", "path to testcase csv")
	nodesFlag := flag.String("nodes",
		"1=127.0.0.1:50051,2=127.0.0.1:50052,3=127.0.0.1:50053,4=127.0.0.1:50054,5=127.0.0.1:50055,6=127.0.0.1:50056,7=127.0.0.1:50057",
		"comma-separated nodeID=addr list",
	)
	timeoutFlag := flag.Duration("timeout", defaultTimeout, "per-request timeout")
	clientAddrFlag := flag.String("client_addr", "127.0.0.1:7000", "address for client reply server")
	flag.Parse()

	clientListenAddr := "127.0.0.1:7000"

	lis, err := net.Listen("tcp", clientListenAddr)
	if err != nil {
		log.Fatalf("client listen error: %v", err)
	}

	grpcServer := grpc.NewServer()
	crs := &ClientReplyServer{
		pending: make(map[pendingKey]*pendingResult),
		f:       2,
	}
	pbftproto.RegisterClientServiceServer(grpcServer, crs)

	go func() {
		log.Printf("[client] listening for replies on %s", clientListenAddr)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("client grpc serve error: %v", err)
		}
	}()
	sets, err := loadTestSets(*csvPath)
	if err != nil {
		log.Fatalf("load test sets: %v", err)
	}
	log.Printf("Loaded %d test sets from %s", len(sets), *csvPath)

	nodeAddrs, err := parseNodesFlag(*nodesFlag)
	if err != nil {
		log.Fatalf("parse -nodes: %v", err)
	}

	nodes, err := dialNodes(nodeAddrs)
	if err != nil {
		log.Fatalf("dial nodes: %v", err)
	}
	defer func() {
		for _, nc := range nodes {
			_ = nc.Conn.Close()
		}
	}()

	clients := newLogicalClients(nodes, *timeoutFlag)
	reader := bufio.NewReader(os.Stdin)

	for _, ts := range sets {
		fmt.Println("====================================================")
		fmt.Printf("Starting Test Set %d\n", ts.ID)
		fmt.Printf("  Live:      %v\n", ts.Live)
		fmt.Printf("  Byzantine: %v\n", ts.Byzantine)
		fmt.Printf("  Attacks:   %v\n", ts.Attacks)
		fmt.Printf("  Txns:\n")
		for _, tx := range ts.Txns {
			fmt.Printf("    %s\n", tx.Raw)
		}
		fmt.Println("Press ENTER to run this set...")
		_, _ = reader.ReadString('\n')

		configureAndResetNodes(nodes, ts)

		var wg sync.WaitGroup
		var cnt int = 0

		for _, tx := range ts.Txns {
			tx := tx
			lc := pickClientForSender(clients, tx.From)

			wg.Add(1)
			go func(c *LogicalClient, t Tx) {
				defer wg.Done()

				c.mu.Lock()
				defer c.mu.Unlock()

				tsVal := t.From + strconv.Itoa(cnt)
				cnt++
				if tsVal == "" {
					tsVal = fmt.Sprintf("%s-%d", t.From, time.Now().UnixNano())
				}

				key := pendingKey{From: t.From, Timestamp: tsVal}
				pr := &pendingResult{done: make(chan struct{})}

				crs.mu.Lock()
				crs.pending[key] = pr
				crs.mu.Unlock()

				req := &pbftproto.ClientRequest{
					From:       t.From,
					To:         t.To,
					Amount:     t.Amount,
					Timestamp:  tsVal,
					ClientAddr: *clientAddrFlag,
				}

				ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
				_, err := nodes[1].Cli.HandleClientRequest(ctx, req)
				cancel()
				if err != nil {
					log.Printf("[client %s,%s] initial send error: %v", t.From, tsVal, err)
				}

				maxRetries := 3
				for attempt := 0; attempt < maxRetries; attempt++ {
					select {
					case <-pr.done:
						if pr.final.Success {
							log.Printf("[client %s,%s] SUCCESS: %s (seq=%d, view=%d)",
								t.From, tsVal, pr.final.Message, pr.final.Seq, pr.final.View)
						} else {
							log.Printf("[client %s,%s] FAIL: %s (seq=%d, view=%d)",
								t.From, tsVal, pr.final.Message, pr.final.Seq, pr.final.View)
						}

						crs.mu.Lock()
						delete(crs.pending, key)
						crs.mu.Unlock()
						return

					case <-time.After(*timeoutFlag):
						log.Printf("[client %s,%s] timeout waiting for replies (attempt %d), retrying",
							t.From, tsVal, attempt+1)

						for _, nc := range nodes {
							ctx2, cancel2 := context.WithTimeout(context.Background(), *timeoutFlag)
							_, _ = nc.Cli.HandleClientRequest(ctx2, req)
							cancel2()
						}
					}
				}

				log.Printf("[client %s,%s] no decision after retries, moving on", t.From, tsVal)
				crs.mu.Lock()
				delete(crs.pending, key)
				crs.mu.Unlock()
			}(lc, tx)
		}

		wg.Wait()
		fmt.Printf("Test Set %d complete.\n", ts.ID)
		for {
			fmt.Println("Admin> Enter command [log <id|all> | db <id|all> | status <seq> | view <id|all> | next]:")
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" || line == "next" {
				break
			}
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			cmd := strings.ToLower(parts[0])
			switch cmd {
			case "log", "db", "view":
				if len(parts) < 2 {
					fmt.Println("Usage:", cmd, "<id|all>")
					continue
				}
				target := strings.ToLower(parts[1])
				if target == "all" {
					for id, nc := range nodes {
						msg := fetchAdmin(nc, strings.ToUpper("PRINT"+cmd), "")
						fmt.Printf("--- %s node %d ---\n%s\n", strings.ToUpper(cmd), id, msg)
					}
				} else {
					nid, err := strconv.ParseUint(target, 10, 64)
					if err != nil {
						fmt.Println("bad node id:", target)
						continue
					}
					if nc, ok := nodes[nid]; ok {
						msg := fetchAdmin(nc, strings.ToUpper("PRINT"+cmd), "")
						fmt.Printf("--- %s node %d ---\n%s\n", strings.ToUpper(cmd), nid, msg)
					} else {
						fmt.Println("unknown node id", nid)
					}
				}
			case "status":
				if len(parts) < 2 {
					fmt.Println("Usage: status <seq>")
					continue
				}
				seq := strings.TrimSpace(parts[1])
				for id, nc := range nodes {
					msg := fetchAdmin(nc, "PRINTSTATUS", seq)
					fmt.Printf("--- STATUS node %d ---\n%s\n", id, msg)
				}
			default:
				fmt.Println("Unknown command. Supported: log, db, status, view, next")
			}
		}
	}

	fmt.Println("All test sets completed.")
}

func fetchAdmin(nc *NodeClient, to string, param string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := &pbftproto.ClientRequest{From: "__ADMIN__", To: to, Amount: 0, Timestamp: param}
	rep, err := nc.Cli.HandleClientRequest(ctx, req)
	if err != nil || rep == nil {
		if err != nil {
			return fmt.Sprintf("error: %v", err)
		}
		return "error: no reply"
	}
	return rep.Message
}
