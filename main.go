package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	ma "github.com/multiformats/go-multiaddr"
)

const KEY_FILE_PATH = "./keys.json"

// provided by libp2p
var defaultBootstrapPeers = []string{
	// "/ip4/147.75.94.249/tcp/4001/p2p/QmSoLueR4xZi6cVtcBAdfVkb9vi53Apnw8kVn5g7YRhbi", // from gpt
	// "/ip4/147.75.94.249/tcp/4001/p2p/QmSoLer265NRgSp2LA3dPaeykiS1J6DifTC88f5uVQKNAd",
	// "/ip4/147.75.94.249/tcp/4001/p2p/QmSoLue2YgpqfSpBzXmtSmF5BJ1MDF8cAsLwea1JHa5hTZ",
	"/ip4/104.131.131.82/tcp/4001/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ", // from perplexity which is from https://www.npmjs.com/package/@libp2p/bootstrap
	"/dnsaddr/bootstrap.libp2p.io/ipfs/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/ipfs/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
}

// KeyPair: public and private keys
type KeyPair struct {
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
}

func LoadKeyPairFromFile() (KeyPair, error) {
	data, err := os.ReadFile(KEY_FILE_PATH)
	if err != nil {
		return KeyPair{}, err
	}
	var keyPair KeyPair
	err = json.Unmarshal(data, &keyPair)
	return keyPair, err
}

func PublicKeyToIdentifier(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return hex.EncodeToString((hash[:8]))
}

func GenerateKeyPair() (KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PublicKey: publicKey, PrivateKey: privateKey}, nil
}

func SaveKeyPair(keyPair KeyPair) error {
	data, err := json.Marshal(keyPair)
	if err != nil {
		return err
	}
	return os.WriteFile(KEY_FILE_PATH, data, 0600) // 0600 ensures only the owner can read/write
}

func DisplayCommands() {
	fmt.Println("\nAvailable Commands:")
	fmt.Println("- `/connect <identifier>`: Connect to a peer using their identifier.")
	fmt.Println("- `/send <message>`: Send a message to the connected peer.")
	fmt.Println("- `/help`: Display the available commands.")
	fmt.Println("- `/exit`: End the session and close the app.")
}

func getBootstrapPeers() []peer.AddrInfo {
	var peers []peer.AddrInfo

	for _, addr := range defaultBootstrapPeers {
		maddr, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			fmt.Println("Error parsing multiaddr: ", err)
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

func startDHTWithBootstrap(ctx context.Context) (host.Host, *dht.IpfsDHT) {
	// 1. Create my own host / node
	host, err := libp2p.New(
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

	// 2. Create DHT (for discovery)
	kdht, err := dht.New(ctx, host)
	if err != nil {
		panic(err)
	}

	// 3. Connect to bootstrap peers
	fmt.Println("\nConnecting to bootstrap peers...")
	peers := getBootstrapPeers()
	var connectedPeers int
	for _, peer := range peers {
		if err := host.Connect(ctx, peer); err != nil {
			fmt.Printf("Failed to connect to bootstrap peer %s: %v\n", peer.ID.String(), err)
		} else {
			connectedPeers++
			fmt.Printf("Successfully connected to bootstrap peer: %s\n", peer.ID.String())
		}
	}
	fmt.Printf("Connected to %d out of %d bootstrap peers\n", connectedPeers, len(peers))

	if err := kdht.Bootstrap(ctx); err != nil {
		panic(err)
	}

	return host, kdht
}

func connectToPeer(ctx context.Context, host host.Host, dht *dht.IpfsDHT, targetIdentifier string) {
	// First, ensure DHT is bootstrapped
	if err := dht.Bootstrap(ctx); err != nil {
		fmt.Printf("DHT bootstrap failed: %v\n", err)
		return
	}

	// Convert the target identifier to a key
	key := fmt.Sprintf("/chat/peer/%s", targetIdentifier)
	fmt.Printf("Searching for peer with identifier: %s\n", targetIdentifier)

	// Try to find the peer's information from the DHT with timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Keep trying to get the value until we succeed or timeout
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Timeout: Could not find peer")
			return
		default:
			peerInfo, err := dht.GetValue(ctx, key)
			if err == nil {
				// Successfully got peer info
				peerAddr, err := ma.NewMultiaddrBytes(peerInfo)
				if err != nil {
					fmt.Printf("Failed to parse peer address: %v\n", err)
					return
				}

				info, err := peer.AddrInfoFromP2pAddr(peerAddr)
				if err != nil {
					fmt.Printf("Failed to get peer info: %v\n", err)
					return
				}

				// Connect to the peer
				if err := host.Connect(ctx, *info); err != nil {
					fmt.Printf("Failed to connect to peer: %v\n", err)
					return
				}

				fmt.Println("Successfully connected!")
				return
			}
			time.Sleep(1 * time.Second) // Wait before retrying
		}
	}
}

func advertisePeer(ctx context.Context, host host.Host, dht *dht.IpfsDHT, identifier string) error {
	// Create a key for this peer
	key := fmt.Sprintf("/chat/peer/%s", identifier)

	// Get all host addresses and create a full multiaddr for each
	var fullAddrs []ma.Multiaddr
	for _, addr := range host.Addrs() {
		fullAddr := addr.Encapsulate(ma.StringCast("/p2p/" + host.ID().String()))
		fullAddrs = append(fullAddrs, fullAddr)
	}

	// Store the first address in the DHT (you could store all addresses if needed)
	if len(fullAddrs) == 0 {
		return fmt.Errorf("no addresses available to advertise")
	}

	// Add timeout for the DHT operation
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Store this peer's address in the DHT with retry
	for i := 0; i < 3; i++ {
		err := dht.PutValue(ctx, key, fullAddrs[0].Bytes())
		if err == nil {
			return nil
		}
		if i < 2 { // Don't sleep after the last attempt
			time.Sleep(2 * time.Second)
		}
	}

	return fmt.Errorf("failed to advertise peer after multiple attempts")
}

func main() {
	fmt.Println("Welcome to Insanely Easy Secure Messenger!")
	fmt.Println("Do you have an existing identifier? (yes/no):")
	var input string
	fmt.Scanln(&input)

	// Identity Management
	var keyPair KeyPair
	var err error
	var identifier string

	if input == "yes" {
		// Load existing identifier
		keyPair, err = LoadKeyPairFromFile()
		if err != nil {
			fmt.Println("Error loading identifier: ", err)
			return
		}
		identifier = PublicKeyToIdentifier(keyPair.PublicKey)
		fmt.Printf("Welcome back %s!\n", identifier)
	} else if input == "no" {
		fmt.Println("Generating you a new key pair...")
		keyPair, err = GenerateKeyPair()
		if err != nil {
			fmt.Println("Error generating key pair for identifier: ", err)
			return
		}
		err = SaveKeyPair(keyPair)
		if err != nil {
			fmt.Println("Error saving generated key pair: ", err)
		}

		fmt.Printf("Saved your key pair to %s!\n", KEY_FILE_PATH)
		identifier = PublicKeyToIdentifier(keyPair.PublicKey)
		fmt.Println("Your identifier: ", identifier)
	}

	// Initialize DHT and join network with the bootstrap peers provided by libp2p
	fmt.Println("Initializing DHT and connecting to the network...")
	ctx := context.Background()
	h, kdht := startDHTWithBootstrap(ctx)
	defer h.Close()

	// Advertise ourselves so others can find us
	err = advertisePeer(ctx, h, kdht, identifier)
	if err != nil {
		fmt.Printf("Failed to advertise peer: %v\n", err)
		return
	}
	fmt.Println("Successfully advertised our peer to the network!")

	// Start the actual app CLI
	fmt.Println("Type '/help' to see available commands.")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		command := scanner.Text()

		if strings.HasPrefix(command, "/help") {
			DisplayCommands()
		} else if strings.HasPrefix(command, "/connect") {
			// Connect to a specific peer by identifier
			parts := strings.SplitN(command, " ", 2)
			if len(parts) != 2 {
				fmt.Println("Usage: /connect <identifier>")
				continue
			}
			targetIdentifier := parts[1]
			fmt.Println("Connecting to peer: ", targetIdentifier)
			connectToPeer(ctx, h, kdht, targetIdentifier)
		} else if strings.HasPrefix(command, "/send") {
			// TODO
			fmt.Println("Sending message to peer...")
		} else if strings.HasPrefix(command, "/exit") {
			fmt.Println("Goodbye! All your chats are deleted.")
			return
		} else {
			fmt.Println("Invalid input option. Type '/help' to see available commands")
		}
	}

	// Initialize DHT and join the network
	fmt.Println("Initializing DHT and connecting to the network...")
}
