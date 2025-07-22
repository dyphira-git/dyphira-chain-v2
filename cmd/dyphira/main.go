package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"dyphira-node/consensus"
	"dyphira-node/core"
	"dyphira-node/crypto"
	"dyphira-node/network"
	"dyphira-node/types"
)

// parseAddress parses an address from either hex or Bech32 format
func parseAddress(addrStr string) (crypto.Address, error) {
	// Check if it's a Bech32 address (starts with "dyp_")
	if strings.HasPrefix(addrStr, "dyp_") {
		return crypto.Bech32ToAddress(addrStr)
	}

	// Otherwise, try to parse as hex address
	return crypto.AddressFromString(addrStr)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "start":
		startNode(args)
	case "create-account":
		createAccount(args)
	case "send":
		sendTransaction(args)
	case "balance":
		getBalance(args)
	case "block":
		getBlock(args)
	case "validators":
		listValidators(args)
	case "genesis":
		createGenesis(args)
	case "connect":
		connectToPeer(args)
	case "peers":
		listPeers(args)
	case "sync":
		syncState(args)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Dyphira L1 Blockchain")
	fmt.Println("Usage: dyphira-node <command> [args]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  start [--port PORT] [--db-path PATH] [--connect PEER]     Start the blockchain node")
	fmt.Println("  create-account                                           Create a new account")
	fmt.Println("  send --from ADDR --to ADDR --value AMT                   Send a transaction")
	fmt.Println("  balance --address ADDR                                   Get account balance")
	fmt.Println("  block --height HEIGHT                                    Get block by height")
	fmt.Println("  validators                                               List all validators")
	fmt.Println("  genesis                                                  Create genesis block")
	fmt.Println("  connect --peer PEER_ADDR                                 Connect to a peer")
	fmt.Println("  peers                                                    List connected peers")
	fmt.Println("  sync --from HEIGHT --to HEIGHT                          Sync blockchain state")
}

func startNode(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	port := fs.Int("port", 8080, "P2P port")
	dbPath := fs.String("db-path", "./dyphira.db", "Database path")
	connectPeer := fs.String("connect", "", "Peer address to connect to")
	fs.Parse(args)

	// Create blockchain
	blockchain, err := core.NewBlockchain(*dbPath)
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Close()

	// Check if genesis block exists
	_, err = blockchain.GetBlockByHeight(0)
	if err != nil {
		log.Println("Genesis block not found, creating...")
		_, err = blockchain.CreateGenesisBlock()
		if err != nil {
			log.Fatalf("Failed to create genesis block: %v", err)
		}
	}

	// Create consensus engine
	dpos := consensus.NewDPoS()

	// Create P2P node
	p2pNode, err := network.NewP2PNode(*port, blockchain, dpos)
	if err != nil {
		log.Fatalf("Failed to create P2P node: %v", err)
	}

	// Start P2P node
	err = p2pNode.Start()
	if err != nil {
		log.Fatalf("Failed to start P2P node: %v", err)
	}

	log.Printf("Dyphira node started on port %d", *port)
	log.Printf("P2P address: %s", p2pNode.GetAddress())

	// Connect to peer if specified
	if *connectPeer != "" {
		log.Printf("Connecting to peer: %s", *connectPeer)
		err = p2pNode.ConnectToPeer(*connectPeer)
		if err != nil {
			log.Printf("Failed to connect to peer: %v", err)
		} else {
			log.Printf("Successfully connected to peer")
		}
	}

	// Start background tasks
	go startBlockProduction(blockchain, dpos, p2pNode)
	go startStateSync(blockchain, p2pNode)

	// Keep the node running
	select {}
}

// startBlockProduction starts the block production process
func startBlockProduction(blockchain *core.Blockchain, dpos *consensus.DPoS, p2pNode *network.P2PNode) {
	ticker := time.NewTicker(2 * time.Second) // Block time
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Create a new block
			block, err := createNewBlock(blockchain, dpos)
			if err != nil {
				log.Printf("Failed to create block: %v", err)
				continue
			}

			// Add block to blockchain
			err = blockchain.AddBlock(block)
			if err != nil {
				log.Printf("Failed to add block: %v", err)
				continue
			}

			// Broadcast block to network
			err = p2pNode.PublishBlock(block)
			if err != nil {
				log.Printf("Failed to broadcast block: %v", err)
			} else {
				log.Printf("Broadcasted block %d", block.Header.Height)
			}

		case <-time.After(10 * time.Second):
			// Timeout - continue
		}
	}
}

// createNewBlock creates a new block
func createNewBlock(blockchain *core.Blockchain, dpos *consensus.DPoS) (*types.Block, error) {
	// Get latest block
	latestBlock, err := blockchain.GetLatestBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	// Create block header
	header := types.BlockHeader{
		PrevHash:           latestBlock.Hash(),
		Height:             latestBlock.Header.Height + 1,
		Timestamp:          time.Now().Unix(),
		Proposer:           crypto.Address{}, // Will be set by consensus
		TxRoot:             crypto.Hash{},    // Will be calculated
		AccountStateRoot:   crypto.Hash{},    // Will be set by blockchain
		ValidatorStateRoot: crypto.Hash{},    // Will be set by blockchain
		TxStateRoot:        crypto.Hash{},    // Will be set by blockchain
	}

	// Create block with empty transactions for now
	block := &types.Block{
		Header:       header,
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	return block, nil
}

// startStateSync starts the state synchronization process
func startStateSync(blockchain *core.Blockchain, p2pNode *network.P2PNode) {
	ticker := time.NewTicker(30 * time.Second) // Sync every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if we need to sync
			currentHeight := blockchain.GetLatestHeight()
			if currentHeight == 0 {
				// Request initial sync
				err := p2pNode.RequestStateSync(0, 100) // Request first 100 blocks
				if err != nil {
					log.Printf("Failed to request state sync: %v", err)
				}
			}

		case <-time.After(60 * time.Second):
			// Timeout - continue
		}
	}
}

func createAccount(args []string) {
	// Generate key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	address := keyPair.GetAddress()
	bech32Address, err := keyPair.GetBech32Address()
	if err != nil {
		log.Fatalf("Failed to generate Bech32 address: %v", err)
	}

	// Create account info
	accountInfo := map[string]interface{}{
		"address":        address.String(),
		"bech32_address": bech32Address,
		"public_key":     fmt.Sprintf("%x", keyPair.PublicKey.X.Bytes()),
		"private_key":    fmt.Sprintf("%x", keyPair.PrivateKey.D.Bytes()),
	}

	// Output as JSON
	output, err := json.MarshalIndent(accountInfo, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal account info: %v", err)
	}

	fmt.Println(string(output))
}

func sendTransaction(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	fromAddr := fs.String("from", "", "Sender address")
	toAddr := fs.String("to", "", "Recipient address")
	value := fs.String("value", "0", "Amount to send")
	privateKey := fs.String("private-key", "", "Private key (hex)")
	fs.Parse(args)

	if *fromAddr == "" || *toAddr == "" || *privateKey == "" {
		log.Fatal("--from, --to, and --private-key are required")
	}

	// Parse addresses (from address not used in this simplified version)
	_, err := parseAddress(*fromAddr)
	if err != nil {
		log.Fatalf("Invalid from address: %v", err)
	}

	to, err := parseAddress(*toAddr)
	if err != nil {
		log.Fatalf("Invalid to address: %v", err)
	}

	// Parse value
	valueInt, ok := new(big.Int).SetString(*value, 10)
	if !ok {
		log.Fatal("Invalid value")
	}

	// Create transaction
	tx := types.Transaction{
		To:    to,
		Value: valueInt,
		Fee:   big.NewInt(1000), // Fixed fee for now
	}

	// Sign transaction
	// In practice, you'd recover the private key from hex
	// For now, we'll just create a placeholder
	log.Println("Transaction created (not signed - private key recovery not implemented)")

	output, err := json.MarshalIndent(tx, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal transaction: %v", err)
	}

	fmt.Println(string(output))
}

func getBalance(args []string) {
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	address := fs.String("address", "", "Account address")
	fs.Parse(args)

	if *address == "" {
		log.Fatal("--address is required")
	}

	// Parse address
	addr, err := parseAddress(*address)
	if err != nil {
		log.Fatalf("Invalid address: %v", err)
	}

	// Create blockchain instance
	blockchain, err := core.NewBlockchain("./dyphira.db")
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Close()

	// Get account
	account, err := blockchain.GetAccount(addr)
	if err != nil {
		log.Fatalf("Failed to get account: %v", err)
	}

	// Convert to Bech32 for display
	bech32Addr, err := crypto.AddressToBech32(addr, "dyp_")
	if err != nil {
		log.Fatalf("Failed to convert address to Bech32: %v", err)
	}

	balanceInfo := map[string]interface{}{
		"address":        addr.String(),
		"bech32_address": bech32Addr,
		"balance":        account.Balance.String(),
		"nonce":          account.Nonce,
	}

	output, err := json.MarshalIndent(balanceInfo, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal balance info: %v", err)
	}

	fmt.Println(string(output))
}

func getBlock(args []string) {
	fs := flag.NewFlagSet("block", flag.ExitOnError)
	height := fs.String("height", "", "Block height")
	dbPath := fs.String("db-path", "./dyphira.db", "Database path")
	fs.Parse(args)

	if *height == "" {
		log.Fatal("--height is required")
	}

	// Parse height
	heightInt, err := strconv.ParseUint(*height, 10, 64)
	if err != nil {
		log.Fatalf("Invalid height: %v", err)
	}

	// Create blockchain instance
	blockchain, err := core.NewBlockchain(*dbPath)
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Close()

	// Get block
	block, err := blockchain.GetBlockByHeight(heightInt)
	if err != nil {
		log.Fatalf("Failed to get block: %v", err)
	}

	output, err := json.MarshalIndent(block, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal block: %v", err)
	}

	fmt.Println(string(output))
}

func listValidators(args []string) {
	// Create blockchain instance
	blockchain, err := core.NewBlockchain("./dyphira.db")
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Close()

	// Get validators
	validators, err := blockchain.GetAllValidators()
	if err != nil {
		log.Fatalf("Failed to get validators: %v", err)
	}

	validatorList := make([]map[string]interface{}, len(validators))
	for i, v := range validators {
		validatorList[i] = map[string]interface{}{
			"self_stake":      v.SelfStake.String(),
			"delegated_stake": v.DelegatedStake.String(),
			"reputation":      v.Reputation,
			"is_online":       v.IsOnline,
			"last_seen":       v.LastSeen,
		}
	}

	output, err := json.MarshalIndent(validatorList, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal validators: %v", err)
	}

	fmt.Println(string(output))
}

func createGenesis(args []string) {
	// Create blockchain
	blockchain, err := core.NewBlockchain("./dyphira.db")
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Close()

	// Create genesis block
	genesis, err := blockchain.CreateGenesisBlock()
	if err != nil {
		log.Fatalf("Failed to create genesis block: %v", err)
	}

	log.Println("Genesis block created successfully")

	output, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal genesis block: %v", err)
	}

	fmt.Println(string(output))
}

func connectToPeer(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	peerAddr := fs.String("peer", "", "Peer address to connect to")
	fs.Parse(args)

	if *peerAddr == "" {
		log.Fatal("--peer is required")
	}

	// Create blockchain instance
	blockchain, err := core.NewBlockchain("./dyphira.db")
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Close()

	// Create consensus engine
	dpos := consensus.NewDPoS()

	// Create P2P node
	p2pNode, err := network.NewP2PNode(0, blockchain, dpos) // Random port
	if err != nil {
		log.Fatalf("Failed to create P2P node: %v", err)
	}
	defer p2pNode.Stop()

	// Start P2P node
	err = p2pNode.Start()
	if err != nil {
		log.Fatalf("Failed to start P2P node: %v", err)
	}

	// Connect to peer
	err = p2pNode.ConnectToPeer(*peerAddr)
	if err != nil {
		log.Fatalf("Failed to connect to peer: %v", err)
	}

	log.Printf("Successfully connected to peer: %s", *peerAddr)
	log.Printf("Local P2P address: %s", p2pNode.GetAddress())

	// Keep connection alive for a bit
	time.Sleep(10 * time.Second)
}

func listPeers(args []string) {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	dbPath := fs.String("db-path", "./dyphira.db", "Database path")
	fs.Parse(args)

	// Create blockchain instance
	blockchain, err := core.NewBlockchain(*dbPath)
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Close()

	// Create consensus engine
	dpos := consensus.NewDPoS()

	// Create P2P node
	p2pNode, err := network.NewP2PNode(0, blockchain, dpos) // Random port
	if err != nil {
		log.Fatalf("Failed to create P2P node: %v", err)
	}
	defer p2pNode.Stop()

	// Start P2P node
	err = p2pNode.Start()
	if err != nil {
		log.Fatalf("Failed to start P2P node: %v", err)
	}

	// Get peers
	peers := p2pNode.GetPeers()

	peerList := make([]map[string]interface{}, len(peers))
	for i, peer := range peers {
		peerList[i] = map[string]interface{}{
			"id":        peer.ID.String(),
			"addresses": peer.Addresses,
			"last_seen": peer.LastSeen,
			"is_new":    peer.IsNew,
		}
	}

	output, err := json.MarshalIndent(peerList, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal peers: %v", err)
	}

	fmt.Println(string(output))
}

func syncState(args []string) {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	fromHeight := fs.Uint64("from", 0, "Starting block height")
	toHeight := fs.Uint64("to", 100, "Ending block height")
	fs.Parse(args)

	// Create blockchain instance
	blockchain, err := core.NewBlockchain("./dyphira.db")
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Close()

	// Create consensus engine
	dpos := consensus.NewDPoS()

	// Create P2P node
	p2pNode, err := network.NewP2PNode(0, blockchain, dpos) // Random port
	if err != nil {
		log.Fatalf("Failed to create P2P node: %v", err)
	}
	defer p2pNode.Stop()

	// Start P2P node
	err = p2pNode.Start()
	if err != nil {
		log.Fatalf("Failed to start P2P node: %v", err)
	}

	// Request state sync
	log.Printf("Requesting state sync for blocks %d-%d", *fromHeight, *toHeight)
	err = p2pNode.RequestStateSync(*fromHeight, *toHeight)
	if err != nil {
		log.Fatalf("Failed to request state sync: %v", err)
	}

	// Wait for sync to complete
	time.Sleep(5 * time.Second)

	log.Printf("State sync completed")
}
