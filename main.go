package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const KEY_FILE_PATH = "./private_key.pem"

// provided by libp2p
var defaultBootstrapPeers = []string{
	"/ip4/104.131.131.82/tcp/4001/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	"/dnsaddr/bootstrap.libp2p.io/ipfs/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/ipfs/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
}

func loadOrGeneratePrivateKey() (crypto.PrivKey, error) {
	// Check if the key file exists
	if _, err := os.Stat(KEY_FILE_PATH); err == nil {
		// Key file exists; load it
		data, err := os.ReadFile(KEY_FILE_PATH)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %v", err)
		}
		privateKey, err := crypto.UnmarshalPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %v", err)
		}
		fmt.Println("Loaded existing private key.")
		return privateKey, nil
	}

	// Key file doesn't exist; generate a new one
	fmt.Println("Generating a new private key...")
	privateKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Save the private key to a file
	data, err := crypto.MarshalPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	err = os.WriteFile(KEY_FILE_PATH, data, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to save private key: %v", err)
	}
	fmt.Printf("Saved new private key to %s\n", KEY_FILE_PATH)
	return privateKey, nil
}

func getBootstrapPeers() []peer.AddrInfo {
	var peers []peer.AddrInfo

	for _, addr := range defaultBootstrapPeers {
		maddr, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			fmt.Println("Error parsing multiaddr: ", err)
			continue
		}
		peerInfo, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			fmt.Println("Error getting AddrInfo from multiaddr: ", err)
			continue
		}
		peers = append(peers, *peerInfo)
	}

	return peers
}

func startDHTWithBootstrap(ctx context.Context, privateKey crypto.PrivKey) (host.Host, *dht.IpfsDHT) {
	// Create the libp2p host
	host, err := libp2p.New(
		libp2p.Identity(privateKey),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
		libp2p.EnableRelay(),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Host created. We are: %s\n", host.ID().String())
	fmt.Println("Listening on:")
	for _, addr := range host.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, host.ID().String())
	}

	// Create the DHT
	kdht, err := dht.New(ctx, host)
	if err != nil {
		panic(err)
	}

	// Connect to bootstrap peers
	fmt.Println("\nConnecting to bootstrap peers...")
	peers := getBootstrapPeers()
	for _, peer := range peers {
		if err := host.Connect(ctx, peer); err != nil {
			fmt.Printf("Failed to connect to bootstrap peer %s: %v\n", peer.ID.String(), err)
		} else {
			fmt.Printf("Successfully connected to bootstrap peer: %s\n", peer.ID.String())
		}
	}

	if err := kdht.Bootstrap(ctx); err != nil {
		panic(err)
	}

	return host, kdht
}

func main() {
	fmt.Println("Welcome to Insanely Easy Secure Messenger!")

	// Load or generate private key
	privateKey, err := loadOrGeneratePrivateKey()
	if err != nil {
		fmt.Printf("Failed to initialize private key: %v\n", err)
		return
	}

	// Generate peer identifier from private key
	pubKey := privateKey.GetPublic()
	pubKeyBytes, err := pubKey.Raw()
	if err != nil {
		fmt.Printf("Failed to get raw public key: %v\n", err)
		return
	}
	hash := sha256.Sum256(pubKeyBytes)
	identifier := hex.EncodeToString(hash[:])
	fmt.Printf("Your identifier: %s\n", identifier)

	// Initialize DHT and connect to the network
	ctx := context.Background()
	h, kdht := startDHTWithBootstrap(ctx, privateKey)
	defer h.Close()

	// Use the DHT later (e.g., for advertising or connecting to peers)
	_ = kdht // Suppress unused variable warning for now

	// CLI Command Loop
	fmt.Println("Type '/help' to see available commands.")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		command := scanner.Text()

		if strings.HasPrefix(command, "/help") {
			fmt.Println("\nAvailable Commands:")
			fmt.Println("- `/connect <identifier>`: Connect to a peer using their identifier.")
			fmt.Println("- `/send <message>`: Send a message to the connected peer.")
			fmt.Println("- `/exit`: End the session and close the app.")
		} else if strings.HasPrefix(command, "/connect") {
			fmt.Println("TODO: Connect to a peer.")
		} else if strings.HasPrefix(command, "/send") {
			fmt.Println("TODO: Send a message.")
		} else if strings.HasPrefix(command, "/exit") {
			fmt.Println("Goodbye! All your chats are deleted.")
			return
		} else {
			fmt.Println("Invalid command. Type '/help' for a list of commands.")
		}
	}
}
