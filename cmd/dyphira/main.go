package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"

	"dyphira-node/consensus"
	"dyphira-node/core"
	"dyphira-node/crypto"

	// "dyphira/network" // Temporarily disabled
	"dyphira-node/types"
)

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
	fmt.Println("  start [--port PORT] [--db-path PATH]     Start the blockchain node")
	fmt.Println("  create-account                           Create a new account")
	fmt.Println("  send --from ADDR --to ADDR --value AMT   Send a transaction")
	fmt.Println("  balance --address ADDR                   Get account balance")
	fmt.Println("  block --height HEIGHT                    Get block by height")
	fmt.Println("  validators                               List all validators")
	fmt.Println("  genesis                                  Create genesis block")
}

func startNode(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	port := fs.Int("port", 8080, "P2P port")
	dbPath := fs.String("db-path", "./dyphira.db", "Database path")
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

	// Create consensus engine (not used yet)
	_ = consensus.NewDPoS()

	// Create P2P node (temporarily disabled)
	// p2pNode, err := network.NewP2PNode(*port)
	// if err != nil {
	// 	log.Fatalf("Failed to create P2P node: %v", err)
	// }

	// Start P2P node (temporarily disabled)
	// err = p2pNode.Start()
	// if err != nil {
	// 	log.Fatalf("Failed to start P2P node: %v", err)
	// }

	log.Printf("Dyphira node started on port %d (P2P networking disabled)", *port)
	// log.Printf("P2P address: %s", p2pNode.GetAddress())

	// Keep the node running
	select {}
}

func createAccount(args []string) {
	// Generate key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	address := keyPair.GetAddress()

	// Create account info
	accountInfo := map[string]interface{}{
		"address":     address.String(),
		"public_key":  fmt.Sprintf("%x", keyPair.PublicKey.X.Bytes()),
		"private_key": fmt.Sprintf("%x", keyPair.PrivateKey.D.Bytes()),
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
	_, err := crypto.AddressFromString(*fromAddr)
	if err != nil {
		log.Fatalf("Invalid from address: %v", err)
	}

	to, err := crypto.AddressFromString(*toAddr)
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
	addr, err := crypto.AddressFromString(*address)
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

	balanceInfo := map[string]interface{}{
		"address": addr.String(),
		"balance": account.Balance.String(),
		"nonce":   account.Nonce,
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
	blockchain, err := core.NewBlockchain("./dyphira.db")
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
