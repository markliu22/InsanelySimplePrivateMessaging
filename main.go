package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const KEY_FILE_PATH = "./keys.json"

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

func main() {
	fmt.Println("Welcome to Insanely Easy Secure Messenger!")
	fmt.Println("Do you have an existing identifier? (yes/no):")
	var input string
	fmt.Scanln(&input)

	// !!!
	var keyPair KeyPair
	var err error
	var identifier string

	if input == "yes" {
		// load existing identifier
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
		} else if strings.HasPrefix(command, "/send") {
		} else if strings.HasPrefix(command, "/exit") {
			fmt.Println("Goodbye! All your chats are deleted.")
			return
		} else {
			fmt.Println("Invalid input option. Type '/help' to see available commands")
		}
	}

}
