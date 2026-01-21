package main

import (
	"crypto/ed25519"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type yamlNode struct {
	ID      uint64 `yaml:"id"`
	Public  string `yaml:"public"`
	Private string `yaml:"private,omitempty"`
}

type yamlDoc struct {
	Nodes []yamlNode `yaml:"nodes"`
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func mustMkdirAll(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("mkdir -p %s: %v", dir, err)
	}
}

func writeYAML(path string, v any, perm os.FileMode) {
	data, err := yaml.Marshal(v)
	if err != nil {
		log.Fatalf("yaml marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
	log.Printf("wrote %s", path)
}

func main() {
	var (
		nNodes = flag.Int("nodes", 7, "number of nodes to generate")
		outDir = flag.String("out", "./keys", "output directory for yaml files")
		prefix = flag.String("prefix", "keys", "output file prefix (e.g. 'keys' -> keys_all.yaml)")
	)
	flag.Parse()

	if *nNodes <= 0 {
		log.Fatal("nodes must be > 0")
	}
	mustMkdirAll(*outDir)

	type pair struct {
		priv ed25519.PrivateKey
		pub  ed25519.PublicKey
	}
	k := make([]pair, *nNodes)

	// 1) generate all keys
	for i := 0; i < *nNodes; i++ {
		pub, priv, err := ed25519.GenerateKey(cryptoRand.Reader)
		if err != nil {
			log.Fatalf("generate key for node %d: %v", i+1, err)
		}
		k[i] = pair{priv: priv, pub: pub}
	}

	// 2) build aggregate docs
	all := yamlDoc{Nodes: make([]yamlNode, 0, *nNodes)}
	pubOnly := yamlDoc{Nodes: make([]yamlNode, 0, *nNodes)}
	for i := 0; i < *nNodes; i++ {
		id := uint64(i + 1)
		all.Nodes = append(all.Nodes, yamlNode{
			ID:      id,
			Public:  b64(k[i].pub),
			Private: b64(k[i].priv),
		})
		pubOnly.Nodes = append(pubOnly.Nodes, yamlNode{
			ID:     id,
			Public: b64(k[i].pub),
		})
	}

	// 3) write main files
	allPath := filepath.Join(*outDir, fmt.Sprintf("%s_all.yaml", *prefix))
	pubPath := filepath.Join(*outDir, fmt.Sprintf("%s_public.yaml", *prefix))
	writeYAML(allPath, all, 0o600) // contains privates
	writeYAML(pubPath, pubOnly, 0o644)

	// 4) write per-node files (all publics + only that node’s private)
	for i := 0; i < *nNodes; i++ {
		id := uint64(i + 1)
		per := yamlDoc{Nodes: make([]yamlNode, 0, *nNodes)}
		for j := 0; j < *nNodes; j++ {
			entry := yamlNode{
				ID:     uint64(j + 1),
				Public: b64(k[j].pub),
			}
			if j == i {
				entry.Private = b64(k[j].priv)
			}
			per.Nodes = append(per.Nodes, entry)
		}
		perPath := filepath.Join(*outDir, fmt.Sprintf("%s_node_%d.yaml", *prefix, id))
		writeYAML(perPath, per, 0o600)
	}
}
