package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ipfs/go-cid"
	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
)

const KEY_FILE_PATH_FORMAT = "./private_key_%d.pem"

// In a p2p system, if you connect to 3 separate nodes from 3 separate networks, you are essentially merging the 3 networks together
// Don't need to worry about this because these default bootstrap nodes are already in the same network; just good for reliability in case one is down
var defaultBootstrapPeers = []string{
	"/ip4/104.131.131.82/tcp/4001/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	"/dnsaddr/bootstrap.libp2p.io/ipfs/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/ipfs/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
}

func loadOrGeneratePrivateKey(instance int) (crypto.PrivKey, error) {
	keyPath := fmt.Sprintf(KEY_FILE_PATH_FORMAT, instance)
	if _, err := os.Stat(keyPath); err == nil {
		data, err := os.ReadFile(keyPath)
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

	fmt.Println("Generating a new private key...")
	privateKey, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	data, err := crypto.MarshalPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	err = os.WriteFile(keyPath, data, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to save private key: %v", err)
	}
	fmt.Printf("Saved new private key to %s\n", keyPath)
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

func startDHTWithBootstrap(ctx context.Context, privateKey crypto.PrivKey, basePort int) (host.Host, *dht.IpfsDHT) {
	host, err := libp2p.New(
		libp2p.Identity(privateKey),
		libp2p.ListenAddrStrings(
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", basePort),   // Listen on all interfaces
			fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", basePort), // Explicitly add localhost
		),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Host created. We are: %s\n", host.ID().String())
	fmt.Println("Listening on:")
	for _, addr := range host.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, host.ID().String())
	}

	kdht, err := dht.New(ctx, host, dht.Mode(dht.ModeServer))
	if err != nil {
		panic(err)
	}

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

// Announce in DHT "I'm here, this is my id"
func advertiseKey(ctx context.Context, h host.Host, kdht *dht.IpfsDHT, identifier string) error {
	fmt.Println("Advertising our node to the DHT...")

	mh, err := multihash.Sum([]byte(identifier), multihash.SHA2_256, -1)
	if err != nil {
		return fmt.Errorf("failed to create multihash: %v", err)
	}

	keyCid := cid.NewCidV1(cid.Raw, mh)

	err = kdht.Provide(ctx, keyCid, true)
	if err != nil {
		return fmt.Errorf("failed to advertise key: %v", err)
	}

	fmt.Printf("Successfully advertised key: %s\n", keyCid.String())
	return nil
}

func discoverPeer(ctx context.Context, h host.Host, kdht *dht.IpfsDHT, identifier string) {
	fmt.Printf("Searching for providers of key: %s\n", identifier)

	mh, err := multihash.Sum([]byte(identifier), multihash.SHA2_256, -1)
	if err != nil {
		fmt.Printf("Failed to create multihash: %v\n", err)
		return
	}

	// CID = Content Identifier
	// In this case, content is just the OG identifier
	// Do this way so we can advertise CID on DHT instead of OG identifier
	// Doing this because this follows IPFS/libp2p conventions where the DHT is primarily designed to find providers of specific content
	keyCid := cid.NewCidV1(cid.Raw, mh)
	// perform async search through DHT network to find any peer that advertised keyCid
	peerChan := kdht.FindProvidersAsync(ctx, keyCid, 1)

	foundPeers := false
	for peerInfo := range peerChan {
		// peerChan non empty means we found at least 1
		foundPeers = true
		fmt.Printf("Found peer: %s\n", peerInfo.ID)

		// Create a new AddrInfo with only localhost addresses
		localAddrInfo := peer.AddrInfo{
			ID: peerInfo.ID,
			Addrs: []multiaddr.Multiaddr{
				multiaddr.StringCast(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 4001)), // For instance 1
				multiaddr.StringCast(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 4002)), // For instance 2
			},
		}

		// Try to connect using local addresses
		if err := h.Connect(ctx, localAddrInfo); err != nil {
			fmt.Printf("Failed to connect to peer via localhost: %v\n", err)
			// If localhost fails, try the original addresses
			if err := h.Connect(ctx, peerInfo); err != nil {
				fmt.Printf("Failed to connect to peer via original addresses: %v\n", err)
				continue
			}
		}

		conns := h.Network().ConnsToPeer(peerInfo.ID)
		if len(conns) > 0 {
			for _, conn := range conns {
				fmt.Printf("  Connected via: %s\n", conn.RemoteMultiaddr())
			}
		}
	}

	if !foundPeers {
		fmt.Println("No providers found for the given key.")
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./program <instance_number>")
		fmt.Println("Example: ./program 1")
		return
	}

	var instance int
	_, err := fmt.Sscanf(os.Args[1], "%d", &instance)
	if err != nil {
		fmt.Printf("Invalid instance number: %v\n", err)
		return
	}

	fmt.Printf("Starting Insanely Easy Secure Messenger (Instance %d)!\n", instance)

	privateKey, err := loadOrGeneratePrivateKey(instance)
	if err != nil {
		fmt.Printf("Failed to initialize private key: %v\n", err)
		return
	}

	pubKey := privateKey.GetPublic()
	pubKeyBytes, err := pubKey.Raw()
	if err != nil {
		fmt.Printf("Failed to get raw public key: %v\n", err)
		return
	}
	hash := sha256.Sum256(pubKeyBytes)
	identifier := hex.EncodeToString(hash[:])
	fmt.Printf("Your identifier: %s\n", identifier)

	basePort := 4000 + instance

	ctx := context.Background()
	h, kdht := startDHTWithBootstrap(ctx, privateKey, basePort)
	defer h.Close()

	fmt.Println("\nType '/help' to see available commands.")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		command := scanner.Text()

		if strings.HasPrefix(command, "/help") {
			fmt.Println("\nAvailable Commands:")
			fmt.Println("- `/advertise`: Advertise your presence to the DHT.")
			fmt.Println("- `/discover <identifier>`: Search for peers advertising the specified identifier.")
			fmt.Println("- `/exit`: End the session and close the app.")
		} else if strings.HasPrefix(command, "/advertise") {
			err = advertiseKey(ctx, h, kdht, identifier)
			if err != nil {
				fmt.Printf("Failed to advertise: %v\n", err)
			} else {
				fmt.Println("Successfully advertised your presence!")
			}
		} else if strings.HasPrefix(command, "/discover") {
			parts := strings.SplitN(command, " ", 2)
			if len(parts) != 2 {
				fmt.Println("Usage: /discover <identifier>")
				continue
			}
			targetIdentifier := parts[1]
			discoverPeer(ctx, h, kdht, targetIdentifier)
		} else if strings.HasPrefix(command, "/exit") {
			fmt.Println("Goodbye! All your chats are deleted.")
			return
		} else {
			fmt.Println("Invalid command. Type '/help' for a list of commands.")
		}
	}
}
