package main

// Server bootup for a single node instance.
// Loads Ed25519 keys from a YAML file and starts both gRPC services.
//
// Example YAML (keys.yaml):
// ---
// nodes:
//   - id: 1
//     public: "MC4CAQAwBQYDK2VwAyEA9jv2ZV4r8K6vD9Y3...<base64 ed25519 public bytes>"
//     private: "MC4CAQAwBQYDK2VwBCIEIAzq5b0lG1k7n1s...<base64 ed25519 private bytes>"
//   - id: 2
//     public: "..."    # replicas only need public
//   - id: 3
//     public: "..."
//
// Run each node in its own terminal, e.g.:
//   go run . -id 1 -port 50051 -primary_id 1 \
//     -peers "2=127.0.0.1:50052,3=127.0.0.1:50053" \
//     -keys_yaml ./keys.yaml
//
// Adjust module import paths below (pbft/proto, etc.) to match your repo layout.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	crypto "pbft/utils"
	"strconv"
	"strings"
	"time"

	pbftproto "pbft/proto"
	// If your crypto/util types are in a different package, update these imports.
	// crypto "pbft/utils"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

// ---- YAML types ----
type keyNode struct {
	ID      uint64 `yaml:"id"`
	Public  string `yaml:"public"`
	Private string `yaml:"private,omitempty"`
}
type keyFile struct {
	Nodes []keyNode `yaml:"nodes"`
}

// peer spec is "id=host:port"
type peerSpec struct {
	id   uint64
	addr string
}

// Exponential backoff sequence: 500ms -> 1s -> 2s -> 4s -> ... capped
func nextBackoff(cur time.Duration) time.Duration {
	if cur <= 0 {
		return 500 * time.Millisecond
	}
	if cur >= 10*time.Second {
		return 10 * time.Second
	}
	return cur * 2
}

// Keeps retrying peers until connected, without blocking the server.
// On success, installs ReplicaServiceClient; if that peer is the primary, also installs PrimaryServiceClient.
func (n *Node) StartPeerDialer(peers []peerSpec, primaryID uint64) {
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // wait for a TCP connect on each attempt
		grpc.WithIdleTimeout(2 * time.Minute),
	}

	type peerState struct {
		backoff time.Duration
	}
	state := make(map[uint64]*peerState)
	for _, p := range peers {
		state[p.id] = &peerState{}
	}

	go func() {
		for {
            for _, p := range peers {
                // already connected?
                n.mu.Lock()
                _, ok := n.ReplicaClients[p.id]
                n.mu.Unlock()
                if ok {
                    continue
                }

				// compute (and log) backoff (we sleep AFTER a failed attempt)
				ps := state[p.id]
				if ps.backoff == 0 {
					ps.backoff = 500 * time.Millisecond
				}

				// attempt a dial with short timeout
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				conn, err := grpc.DialContext(ctx, p.addr, dialOpts...)
				cancel()

				if err != nil {
					log.Printf("[node %d] dial -> peer %d @ %s failed: %v (retry in %v)", n.ID, p.id, p.addr, err, ps.backoff)
					time.Sleep(ps.backoff)
					ps.backoff = nextBackoff(ps.backoff)
					continue
				}

            // success: install client(s) and reset backoff (guard map writes)
            n.mu.Lock()
            n.ReplicaClients[p.id] = pbftproto.NewReplicaServiceClient(conn)
            n.PrimaryClients[p.id] = pbftproto.NewPrimaryServiceClient(conn)
            n.mu.Unlock()
            log.Printf("[node %d] connected clients -> %d @ %s", n.ID, p.id, p.addr)

				ps.backoff = 0
			}
			// small idle delay between scans
			time.Sleep(1 * time.Second)
		}
	}()
}

func parsePeers(peersCSV string) ([]peerSpec, error) {
	parts := strings.Split(strings.TrimSpace(peersCSV), ",")
	if len(parts) == 1 && parts[0] == "" {
		return nil, nil
	}
	out := make([]peerSpec, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("bad peer '%s', expected id=host:port", p)
		}
		id, err := strconv.ParseUint(kv[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad peer id in '%s': %w", p, err)
		}
		out = append(out, peerSpec{id: id, addr: kv[1]})
	}
	return out, nil
}

func loadKeysYAML(path string) (*keyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := yaml.Unmarshal(b, &kf); err != nil {
		return nil, err
	}
	return &kf, nil
}

func decodeB64(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}

// fireDemoBatchAfterPeers waits until *all* peers are connected, then fires K requests concurrently.
// Only runs on the primary.
// func (n *Node) fireDemoBatchAfterPeers(peers []peerSpec, primaryID uint64, K int) {
// 	if n.ID != primaryID || K <= 0 {
// 		return
// 	}
// 	expected := len(peers)

// 	go func() {
// 		ticker := time.NewTicker(300 * time.Millisecond)
// 		defer ticker.Stop()

// 		for {
// 			<-ticker.C
// 			n.mu.Lock()
// 			ready := 0
// 			for _, p := range peers {
// 				if _, ok := n.ReplicaClients[p.id]; ok {
// 					ready++
// 				}
// 			}
// 			n.mu.Unlock()

// 			if ready == expected {
// 				// Small grace period to let handlers settle.
// 				time.Sleep(1 * time.Second)

// 				log.Printf("[node %d] all peers connected (%d/%d). Firing %d demo txs concurrently...",
// 					n.ID, ready, expected, K)

// 				// Build K requests. We keep the same (A->B,6) but unique timestamps "A1", "A2", ...
// 				// If you want varied senders/amounts, randomize below.
// 				reqs := make([]*pbftproto.ClientRequest, 0, K)
// 				// for i := 1; i <= K; i++ {
// 				reqs = append(reqs, &pbftproto.ClientRequest{
// 					From:      "A",
// 					To:        "B",
// 					Amount:    6,
// 					Timestamp: fmt.Sprintf("A%d", 1), // unique -> unique digest
// 				})
// 				reqs = append(reqs, &pbftproto.ClientRequest{
// 					From:      "C",
// 					To:        "A",
// 					Amount:    4,
// 					Timestamp: fmt.Sprintf("C%d", 1), // unique -> unique digest
// 				})
// 				reqs = append(reqs, &pbftproto.ClientRequest{
// 					From:      "A",
// 					To:        "F",
// 					Amount:    12,
// 					Timestamp: fmt.Sprintf("A%d", 2), // unique -> unique digest
// 				})
// 				// reqs = append(reqs, &pbftproto.ClientRequest{
// 				// 	From:      "A",
// 				// 	To:        "A",
// 				// 	Amount:    0,
// 				// 	Timestamp: fmt.Sprintf("A%d", 3), // unique -> unique digest
// 				// })
// 				// }

// 				// Barrier so all goroutines start at roughly the same moment.
// 				start := make(chan struct{})
// 				var wg sync.WaitGroup
// 				wg.Add(len(reqs))

// 				for _, r := range reqs {
// 					req := r
// 					go func() {
// 						defer wg.Done()
// 						<-start
// 						if err := n.PrimaryBroadcastPrePrepare(context.Background(), req); err != nil {
// 							log.Printf("[node %d] demo preprepare failed: %v", n.ID, err)
// 						}
// 					}()
// 				}

// 				close(start) // launch all
// 				// We do not block on wg here; the server keeps serving while the batch runs.
// 				return
// 			}
// 		}
// 	}()
// }

func parseUintSetCSV(s string) map[uint64]bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	m := make(map[uint64]bool)
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		v, err := strconv.ParseUint(tok, 10, 64)
		if err == nil {
			m[v] = true
		}
	}
	return m
}

func main() {
	// ---- Flags ----
	var (
		idFlag        = flag.Uint64("id", 1, "this node ID (uint64)")
		portFlag      = flag.Int("port", 50051, "listen port")
		peersFlag     = flag.String("peers", "", "comma-separated peers 'id=host:port', excluding self")
		primaryIDFlag = flag.Uint64("primary_id", 1, "current primary node ID")
		lowWMFlag     = flag.Uint64("lowwm", 0, "low watermark (h)")
		highWMFlag    = flag.Uint64("highwm", 100000, "high watermark (H)")
		viewFlag      = flag.Uint64("view", 0, "initial view number (v)")
		seqFlag       = flag.Uint64("seq", 0, "initial sequence number (n)")
		keysYAMLFlag  = flag.String("keys_yaml", "./keys.yaml", "YAML file containing per-node Ed25519 keys")
		// Fault injection toggles (default false)
		disabledFlag        = flag.Bool("disabled", false, "simulate disabled/crash (drops all)")
		inDarkAttackFlag    = flag.Bool("dark", false, "simulate in-dark attack (primary withholds to a victim)")
		darkPeersFlag       = flag.String("dark_peers", "", "comma-separated peer IDs to keep in the dark, e.g. \"2,4,6\"")
		equivocationFlag    = flag.Bool("equivocate", false, "simulate equivocation by primary")
		equivPeersFlag      = flag.String("equiv_peers", "", "comma-separated peer IDs to receive seq n (others get n+1), e.g. \"2,4,6\"")
		crashFlag           = flag.Bool("crash", false, "simulate crash (drops all)")
		timeAttackFlag      = flag.Bool("delay", false, "simulate time/delay attack")
		signatureAttackFlag = flag.Bool("badSig", false, "simulate signature attack")
		fastPathFlag       = flag.Bool("fastpath", false, "enable optimistic fast path (SBFT-like)")
		fastMsFlag         = flag.Int("fast_ms", 200, "fast path wait window in ms")
	)
	flag.Parse()

	nodeID := *idFlag
	listenAddr := fmt.Sprintf(":%d", *portFlag)

	// ---- Load keys from YAML ----
	kf, err := loadKeysYAML(*keysYAMLFlag)
	if err != nil {
		log.Fatalf("load keys yaml: %v", err)
	}
	pubKeys := make(map[uint64]ed25519.PublicKey)
	var selfPriv ed25519.PrivateKey
	for _, kn := range kf.Nodes {
		if kn.Public == "" {
			log.Fatalf("keys yaml: node %d missing public key", kn.ID)
		}
		pubBytes, err := decodeB64(kn.Public)
		if err != nil {
			log.Fatalf("decode public key for node %d: %v", kn.ID, err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			log.Fatalf("public key size invalid for node %d", kn.ID)
		}
		pub := ed25519.PublicKey(pubBytes)
		pubKeys[kn.ID] = pub

		if kn.ID == nodeID {
			if kn.Private == "" {
				log.Fatalf("keys yaml: node %d missing private key", kn.ID)
			}
			privBytes, err := decodeB64(kn.Private)
			if err != nil {
				log.Fatalf("decode private key for node %d: %v", kn.ID, err)
			}
			if len(privBytes) != ed25519.PrivateKeySize {
				log.Fatalf("private key size invalid for node %d", kn.ID)
			}
			selfPriv = ed25519.PrivateKey(privBytes)
		}
	}
	if selfPriv == nil {
		log.Fatalf("no private key found for node %d in %s", nodeID, *keysYAMLFlag)
	}

    // ---- Build Node ----
    // NOTE: Adjust Node/ReplicaServer/PrimaryServer types and imports to your package.
    n := &Node{
        ID:      nodeID,
        View:    *viewFlag,
        Seq:     *seqFlag,
        LowWM:   *lowWMFlag,
        HighWM:  *highWMFlag,
		PrivKey: selfPriv,
		PubKeys: pubKeys,
		Log:     make(map[uint64]*crypto.Log),
		// ViewChangeRecords: make(map[uint64]ViewChangeInfo),
		DB:              nil, // TODO: plug your storage if needed
        // Disabled means node is fully down. Do not conflate with Crash.
        Disabled:        *disabledFlag,
		InDarkAttack:    *inDarkAttackFlag,
		DarkPeers:       parseUintSetCSV(*darkPeersFlag),
		Equivocation:    *equivocationFlag,
		EquivocatePeers: parseUintSetCSV(*equivPeersFlag),
		Crash:           *crashFlag,
		TimeAttack:      *timeAttackFlag,
		SignatureAttack: *signatureAttackFlag,
		OptimisticFastPath: *fastPathFlag,
		fastPathTimeout:    time.Duration(*fastMsFlag) * time.Millisecond,
		ReplicaClients:  make(map[uint64]pbftproto.ReplicaServiceClient),
		PrimaryClients:  make(map[uint64]pbftproto.PrimaryServiceClient),

		viewChangeMsgs: make(map[uint64]map[uint64]*pbftproto.ViewChangeMsg),
		// acksBySeq:       make(map[uint64]map[string]struct{}),
		completedAck:  make(map[phaseKey]bool),
		quorumReached: make(map[uint64]bool),
        ackChans:      make(map[phaseKey]chan crypto.AckInfo),

        timerDuration: 6 * time.Second,
    }

	if n.Disabled {
		log.Printf("[node %d] DISABLED: node will not participate in PBFT", n.ID)
	}
	n.DefaultDB()

	// ---- Start gRPC server ----
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen(%s): %v", listenAddr, err)
	}
	grpcServer := grpc.NewServer()

	// Register servers (both services live on every node)
	replicaSrv := &ReplicaServer{Node: n}
	primarySrv := &PrimaryServer{Node: n}
	pbftproto.RegisterReplicaServiceServer(grpcServer, replicaSrv)
	pbftproto.RegisterPrimaryServiceServer(grpcServer, primarySrv)

    go func() {
        log.Printf("[node %d] gRPC serving on %s (view=%d seq=%d, primary=%d) fastpath=%v fast_ms=%d", nodeID, listenAddr, n.View, n.Seq, *primaryIDFlag, n.OptimisticFastPath, int(n.fastPathTimeout/time.Millisecond))
        if err := grpcServer.Serve(lis); err != nil {
            log.Fatalf("gRPC Serve: %v", err)
        }
    }()

	// ---- Connect to peers ----
    peers, err := parsePeers(*peersFlag)
    if err != nil {
        log.Fatalf("parse peers: %v", err)
    }
    // Fix cluster size for primary mapping
    n.TotalNodes = uint64(len(peers) + 1)
    n.StartPeerDialer(peers, *primaryIDFlag)
	// n.fireDemoBatchAfterPeers(peers, *primaryIDFlag, 5)
	// ---- Block forever ----
	select {}
}
