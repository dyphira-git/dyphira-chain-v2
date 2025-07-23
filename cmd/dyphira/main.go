package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create blockchain
	blockchain, err := core.NewBlockchain(*dbPath)
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}
	defer func() {
		log.Println("Closing blockchain...")
		if err := blockchain.Close(); err != nil {
			log.Printf("Error closing blockchain: %v", err)
		}
	}()

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
	dpos := consensus.NewDPoS(blockchain)

	// Add sample validators for testing
	log.Println("Adding sample validators to consensus system...")
	for i := 0; i < 10; i++ {
		// Create a sample key pair for each validator
		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			log.Printf("Failed to generate key pair for validator %d: %v", i, err)
			continue
		}

		validator := &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(int64(10000 + i*1000)), // Varying stakes
			DelegatedStake: big.NewInt(int64(5000 + i*500)),   // Varying delegations
			Reputation:     uint64(50 + i*5),                  // Varying reputation
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
			Delegators:     make(map[crypto.Address]*big.Int),
			TotalRewards:   big.NewInt(0),
			BlocksProposed: 0,
			BlocksApproved: 0,
		}

		err = dpos.AddValidator(validator)
		if err != nil {
			log.Printf("Failed to add validator %d: %v", i, err)
		} else {
			log.Printf("Added validator %d: %s (stake: %s, reputation: %d)",
				i+1, validator.Address.String(), validator.GetTotalStake().String(), validator.Reputation)
		}
	}

	// Elect initial committee
	log.Println("Electing initial committee...")
	err = dpos.ElectCommittee()
	if err != nil {
		log.Printf("Failed to elect initial committee: %v", err)
	} else {
		log.Printf("Initial committee elected with %d members", len(dpos.GetCommittee()))
	}

	// Create P2P node
	p2pNode, err := network.NewP2PNode(*port, blockchain, dpos)
	if err != nil {
		log.Fatalf("Failed to create P2P node: %v", err)
	}
	defer func() {
		log.Println("Stopping P2P node...")
		if err := p2pNode.Stop(); err != nil {
			log.Printf("Error stopping P2P node: %v", err)
		}
	}()

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

	// Create wait group for background tasks
	var wg sync.WaitGroup

	// Start background tasks with context
	wg.Add(1)
	go func() {
		defer wg.Done()
		startBlockProduction(ctx, blockchain, dpos, p2pNode)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startStateSync(ctx, blockchain, p2pNode)
	}()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Node is running. Press Ctrl+C to stop gracefully...")

	// Wait for shutdown signal
	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)
		cancel() // Cancel context to stop background tasks
	case <-ctx.Done():
		log.Println("Context cancelled, shutting down...")
	}

	// Wait for background tasks to finish (with timeout)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All background tasks completed")
	case <-time.After(10 * time.Second):
		log.Println("Timeout waiting for background tasks, forcing shutdown")
	}

	log.Println("Node shutdown complete")
}

// startBlockProduction starts the block production process
func startBlockProduction(ctx context.Context, blockchain *core.Blockchain, dpos *consensus.DPoS, p2pNode *network.P2PNode) {
	ticker := time.NewTicker(2 * time.Second)          // Block time
	stateLogTicker := time.NewTicker(30 * time.Second) // Log consensus state every 30 seconds
	defer ticker.Stop()
	defer stateLogTicker.Stop()

	log.Println("Block production started")

	for {
		select {
		case <-ctx.Done():
			log.Println("Block production stopped")
			return
		case <-stateLogTicker.C:
			// Log consensus state periodically
			dpos.LogConsensusState()
		case <-ticker.C:
			// Get current proposer
			proposer, err := dpos.GetProposer()
			if err != nil {
				log.Printf("Failed to get proposer: %v", err)
				continue
			}

			log.Printf("Current proposer for next block: %s", proposer.Address.String())

			// Create a new block
			block, err := createNewBlock(blockchain, dpos)
			if err != nil {
				log.Printf("Failed to create block: %v", err)
				continue
			}

			log.Printf("Block %d created successfully by proposer %s", block.Header.Height, proposer.Address.String())

			// Add block to blockchain
			err = blockchain.AddBlock(block)
			if err != nil {
				log.Printf("Failed to add block: %v", err)
				continue
			}

			log.Printf("Block %d added to blockchain successfully", block.Header.Height)

			// Update consensus state
			err = dpos.ProcessBlock(block)
			if err != nil {
				log.Printf("Failed to process block in consensus: %v", err)
			} else {
				log.Printf("Block %d processed in consensus successfully", block.Header.Height)
			}

			// Check for epoch transition AFTER processing the block
			if dpos.ShouldStartNewEpoch() {
				log.Printf("Epoch transition detected after processing block %d", block.Header.Height)
				err := dpos.StartNewEpoch()
				if err != nil {
					log.Printf("Failed to start new epoch: %v", err)
				}
			}

			// Broadcast block to network
			err = p2pNode.PublishBlock(block)
			if err != nil {
				log.Printf("Failed to broadcast block: %v", err)
			} else {
				log.Printf("Broadcasted block %d to network", block.Header.Height)
			}
		}
	}
}

// createNewBlock creates a new block using the DPoS consensus engine
func createNewBlock(blockchain *core.Blockchain, dpos *consensus.DPoS) (*types.Block, error) {
	log.Printf("Creating new block at height %d", blockchain.GetLatestHeight()+1)

	// Get current proposer
	proposer, err := dpos.GetProposer()
	if err != nil {
		return nil, fmt.Errorf("failed to get proposer: %w", err)
	}

	log.Printf("Block proposer selected: %s", proposer.Address.String())

	// Create a temporary key pair for the proposer (in real implementation, this would be the actual proposer's key)
	// For now, we'll create a dummy key pair for demonstration
	proposerKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate proposer key pair: %w", err)
	}

	// Use the DPoS CreateBlock method which handles transaction verification and block creation
	block, err := dpos.CreateBlock(proposerKeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to create block: %w", err)
	}

	log.Printf("Block %d created successfully with %d transactions", block.Header.Height, len(block.Transactions))

	return block, nil
}

// startStateSync starts the state synchronization process
func startStateSync(ctx context.Context, blockchain *core.Blockchain, p2pNode *network.P2PNode) {
	ticker := time.NewTicker(30 * time.Second) // Sync every 30 seconds
	defer ticker.Stop()

	log.Println("State sync started")

	for {
		select {
		case <-ctx.Done():
			log.Println("State sync stopped")
			return
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
	dpos := consensus.NewDPoS(blockchain)

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
	dpos := consensus.NewDPoS(blockchain)

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
	dpos := consensus.NewDPoS(blockchain)

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
