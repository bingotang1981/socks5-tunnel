// Command tunnel starts the SecureSOCKS5 tunnel in client or server mode.
//
// Usage:
//
//	tunnel client -config client.json
//	tunnel server -config server.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/bingotang1981/socks5-tunnel/internal/client"
	"github.com/bingotang1981/socks5-tunnel/internal/server"
)

type clientConfig struct {
	ServerAddr  string `json:"server_addr"`
	Key         string `json:"key"`
	ListenAddr  string `json:"listen_addr"`
	SniffDomain bool   `json:"sniff_domain"`
}

type serverConfig struct {
	ListenAddr string `json:"listen_addr"`
	Key        string `json:"key"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	sub := os.Args[1]
	switch sub {
	case "client":
		runClient(os.Args[2:])
	case "server":
		runServer(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n", sub)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `SecureSOCKS5 Tunnel — encrypted SOCKS5 proxy tunnel.

Usage:
  tunnel client -config <file>   Start in client mode
  tunnel server -config <file>   Start in server mode
`)
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	configPath := fs.String("config", "client.json", "path to client config file")
	fs.Parse(args)

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}

	var cfg clientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	if len(cfg.Key) != 32 {
		log.Fatalf("key must be exactly 32 bytes (got %d)", len(cfg.Key))
	}

	c := client.New(cfg.ListenAddr, cfg.ServerAddr, []byte(cfg.Key), cfg.SniffDomain)
	log.Printf("Starting SecureSOCKS5 client on %s -> %s", cfg.ListenAddr, cfg.ServerAddr)
	if err := c.Run(); err != nil {
		log.Fatalf("client error: %v", err)
	}
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", "server.json", "path to server config file")
	fs.Parse(args)

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}

	var cfg serverConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	if len(cfg.Key) != 32 {
		log.Fatalf("key must be exactly 32 bytes (got %d)", len(cfg.Key))
	}

	s := server.New(cfg.ListenAddr, []byte(cfg.Key))
	log.Printf("Starting SecureSOCKS5 server on %s", cfg.ListenAddr)
	if err := s.Run(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
