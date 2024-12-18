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

// Modified to include instance number
const KEY_FILE_PATH_FORMAT = "./private_key_%d.pem"

var defaultBootstrapPeers = []string{
	"/ip4/104.131.131.82/tcp/4001/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	"/dnsaddr/bootstrap.libp2p.io/ipfs/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/ipfs/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
}

// Modified to accept instance number
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
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", basePort)),
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

	kdht, err := dht.New(ctx, host)
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

func advertiseKey(ctx context.Context, kdht *dht.IpfsDHT, identifier string) error {
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

func discoverPeer(ctx context.Context, kdht *dht.IpfsDHT, identifier string) {
	fmt.Printf("Searching for providers of key: %s\n", identifier)

	mh, err := multihash.Sum([]byte(identifier), multihash.SHA2_256, -1)
	if err != nil {
		fmt.Printf("Failed to create multihash: %v\n", err)
		return
	}

	keyCid := cid.NewCidV1(cid.Raw, mh)

	peerChan := kdht.FindProvidersAsync(ctx, keyCid, 1)

	foundPeers := false
	for peerInfo := range peerChan {
		foundPeers = true
		fmt.Printf("Found peer: %s\n", peerInfo.ID)
		if len(peerInfo.Addrs) > 0 {
			for _, addr := range peerInfo.Addrs {
				fmt.Printf("  Address: %s\n", addr)
			}
			fmt.Println("You can attempt to connect to this peer using the '/connect' command.")
		} else {
			fmt.Println("Peer found, but no addresses are available.")
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
			err = advertiseKey(ctx, kdht, identifier)
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
			discoverPeer(ctx, kdht, targetIdentifier)
		} else if strings.HasPrefix(command, "/exit") {
			fmt.Println("Goodbye! All your chats are deleted.")
			return
		} else {
			fmt.Println("Invalid command. Type '/help' for a list of commands.")
		}
	}
}
