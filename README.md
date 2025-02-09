# Insanely Simple P2P Messenger

A lightweight, secure peer-to-peer messenger with no central servers or persistent data.

## Key Features

- **No Persistent Data**: Messages and account data are deleted when you close the app
- **No Central Servers**: Pure peer-to-peer communication
- **End-to-End Encryption**: TLS encryption for all communications
- **Simple Identity**: Share your identifier once to start chatting

## How It Works

1. **Identity & Security**:
   - Each instance generates a 2048-bit RSA key pair on first launch
   - Your identifier is a SHA-256 hash of your public key
   - All connections use TLS (Transport Layer Security) encryption
   - Private keys are stored locally in PEM format and never shared

2. **Peer Discovery**:
   - Uses a Distributed Hash Table (DHT) for peer discovery
   - When you `/advertise`, your presence is announced to the DHT network
   - Other peers can find you using `/discover` with your identifier
   - Initial DHT connection uses public bootstrap nodes provided by libp2p

3. **Connection Flow**:
   - Alice starts messenger and gets her identifier (hash of her public key)
   - Alice runs `/advertise` to announce her presence on the DHT
   - Alice shares her identifier with Bob (via any channel)
   - Bob starts messenger and runs `/discover <Alice's identifier>`
   - A secure TLS connection is established between Alice and Bob

## Quick Start

1. Clone this repo and build:
```
go mod tidy
go build -o messenger
```

2. Start first instance:

In terminal 1:
```
./messenger 1
/advertise
```
You'll see "Your identifier: abc123..." - share this with others

3. Start second instance:

```
./messenger 2
/discover abc123... # Paste the identifier from step 2
```

## Commands
- `/advertise`: Make yourself discoverable to others
- `/discover <id>`: Connect to another user using their identifier
- `/help`: Show all available commands
- `/exit`: Close the app and delete all data