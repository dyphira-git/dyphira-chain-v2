package core

import (
	"fmt"
	"log"
	"math/big"
	"time"

	"dyphira-node/crypto"
	"dyphira-node/state"
	"dyphira-node/types"
)

// Blockchain represents the Dyphira blockchain
type Blockchain struct {
	storage       *state.Storage
	stateMachines *state.StateMachines
	latest        uint64
}

// NewBlockchain creates a new blockchain instance
func NewBlockchain(dbPath string) (*Blockchain, error) {
	storage, err := state.NewStorage(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	bc := &Blockchain{
		storage:       storage,
		stateMachines: state.NewStateMachines(),
	}

	// Load latest block
	latest, err := storage.GetLatestBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}
	bc.latest = latest

	return bc, nil
}

// Close closes the blockchain
func (bc *Blockchain) Close() error {
	return bc.storage.Close()
}

// CreateGenesisBlock creates the genesis block
func (bc *Blockchain) CreateGenesisBlock() (*types.Block, error) {
	// Create genesis block
	genesis := &types.Block{
		Header: types.BlockHeader{
			PrevHash:           crypto.Hash{},
			Height:             0,
			Timestamp:          time.Now().Unix(),
			Proposer:           crypto.Address{},
			TxRoot:             crypto.Hash{},
			AccountStateRoot:   bc.stateMachines.GetAccountStateRoot(),
			ValidatorStateRoot: bc.stateMachines.GetValidatorStateRoot(),
			TxStateRoot:        bc.stateMachines.GetTransactionStateRoot(),
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	// Store genesis block
	err := bc.storage.StoreGenesis(genesis)
	if err != nil {
		return nil, fmt.Errorf("failed to store genesis block: %w", err)
	}

	// Set as latest block
	err = bc.storage.SetLatestBlock(0)
	if err != nil {
		return nil, fmt.Errorf("failed to set latest block: %w", err)
	}

	bc.latest = 0
	return genesis, nil
}

// AddBlock adds a new block to the blockchain
func (bc *Blockchain) AddBlock(block *types.Block) error {
	// Validate block
	err := bc.ValidateBlock(block)
	if err != nil {
		return fmt.Errorf("block validation failed: %w", err)
	}

	// Process transactions
	err = bc.ProcessTransactions(block.Transactions)
	if err != nil {
		return fmt.Errorf("failed to process transactions: %w", err)
	}

	// Add finalized transactions to state machines
	for _, tx := range block.Transactions {
		err = bc.stateMachines.AddTransaction(&tx)
		if err != nil {
			return fmt.Errorf("failed to add transaction to state machines: %w", err)
		}
	}

	// Commit state transition
	err = bc.stateMachines.CommitStateTransition()
	if err != nil {
		return fmt.Errorf("failed to commit state transition: %w", err)
	}

	// Update block state roots
	block.Header.AccountStateRoot = bc.stateMachines.GetAccountStateRoot()
	block.Header.ValidatorStateRoot = bc.stateMachines.GetValidatorStateRoot()
	block.Header.TxStateRoot = bc.stateMachines.GetTransactionStateRoot()

	// Store block
	err = bc.storage.StoreBlock(block)
	if err != nil {
		return fmt.Errorf("failed to store block: %w", err)
	}

	// Update latest block
	bc.latest = block.Header.Height
	err = bc.storage.SetLatestBlock(bc.latest)
	if err != nil {
		return fmt.Errorf("failed to set latest block: %w", err)
	}

	return nil
}

// ValidateBlock validates a block
func (bc *Blockchain) ValidateBlock(block *types.Block) error {
	if block == nil {
		return fmt.Errorf("block cannot be nil")
	}

	log.Printf("Validating block %d", block.Header.Height)

	// Check block height
	if block.Header.Height != bc.latest+1 {
		log.Printf("Invalid block height: expected %d, got %d", bc.latest+1, block.Header.Height)
		return fmt.Errorf("invalid block height: expected %d, got %d", bc.latest+1, block.Header.Height)
	}

	// Check previous hash
	latestBlock, err := bc.GetLatestBlock()
	if err != nil {
		log.Printf("Failed to get latest block for validation: %v", err)
		return fmt.Errorf("failed to get latest block: %w", err)
	}
	if block.Header.PrevHash != latestBlock.Hash() {
		log.Printf("Invalid previous hash for block %d", block.Header.Height)
		return fmt.Errorf("invalid previous hash")
	}

	log.Printf("Block %d basic validation passed (height and prev hash)", block.Header.Height)

	// Validate transactions
	log.Printf("Validating %d transactions in block %d", len(block.Transactions), block.Header.Height)
	for i, tx := range block.Transactions {
		log.Printf("Validating transaction %d/%d in block %d", i+1, len(block.Transactions), block.Header.Height)
		err := bc.ValidateTransaction(&tx)
		if err != nil {
			log.Printf("Transaction %d/%d validation failed: %v", i+1, len(block.Transactions), err)
			return fmt.Errorf("invalid transaction: %w", err)
		}
		log.Printf("Transaction %d/%d validation passed", i+1, len(block.Transactions))
	}

	// Check transaction root
	expectedTxRoot := bc.calculateTxRoot(block.Transactions)
	if block.Header.TxRoot != expectedTxRoot {
		log.Printf("Invalid transaction root for block %d: expected %s, got %s",
			block.Header.Height, expectedTxRoot.String(), block.Header.TxRoot.String())
		return fmt.Errorf("invalid transaction root")
	}

	log.Printf("Block %d validation completed successfully", block.Header.Height)
	return nil
}

// ValidateTransaction validates a transaction
func (bc *Blockchain) ValidateTransaction(tx *types.Transaction) error {
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}

	log.Printf("Validating transaction: Nonce=%d, To=%s, Value=%s, Type=%d",
		tx.Nonce, tx.To.String(), tx.Value.String(), tx.Type)

	// Check transaction signature
	if !tx.Verify() {
		log.Printf("Transaction signature verification failed")
		return fmt.Errorf("invalid transaction signature")
	}
	log.Printf("Transaction signature verification passed")

	// Get sender account
	sender, err := bc.getSenderAddress(tx)
	if err != nil {
		log.Printf("Failed to get sender address: %v", err)
		return fmt.Errorf("failed to get sender address: %w", err)
	}
	log.Printf("Transaction sender: %s", sender.String())

	account, err := bc.stateMachines.GetAccount(sender)
	if err != nil {
		log.Printf("Failed to get sender account %s: %v", sender.String(), err)
		return fmt.Errorf("failed to get sender account: %w", err)
	}

	// Check nonce
	if tx.Nonce != account.Nonce {
		log.Printf("Invalid nonce: expected %d, got %d", account.Nonce, tx.Nonce)
		return fmt.Errorf("invalid nonce: expected %d, got %d", account.Nonce, tx.Nonce)
	}
	log.Printf("Transaction nonce validation passed: %d", tx.Nonce)

	// Check balance
	totalCost := new(big.Int).Add(tx.Value, tx.Fee)
	if account.Balance.Cmp(totalCost) < 0 {
		log.Printf("Insufficient balance: account has %s, transaction requires %s",
			account.Balance.String(), totalCost.String())
		return fmt.Errorf("insufficient balance")
	}
	log.Printf("Transaction balance validation passed: account balance %s >= required %s",
		account.Balance.String(), totalCost.String())

	// Check value and fee are positive
	if tx.Value.Cmp(big.NewInt(0)) < 0 {
		log.Printf("Negative transaction value: %s", tx.Value.String())
		return fmt.Errorf("negative value")
	}
	if tx.Fee.Cmp(big.NewInt(0)) < 0 {
		log.Printf("Negative transaction fee: %s", tx.Fee.String())
		return fmt.Errorf("negative fee")
	}

	log.Printf("Transaction validation completed successfully")
	return nil
}

// ProcessTransactions processes a list of transactions
func (bc *Blockchain) ProcessTransactions(transactions []types.Transaction) error {
	log.Printf("Processing %d transactions", len(transactions))

	for i, tx := range transactions {
		log.Printf("Processing transaction %d/%d", i+1, len(transactions))
		err := bc.ProcessTransaction(&tx)
		if err != nil {
			log.Printf("Failed to process transaction %d/%d: %v", i+1, len(transactions), err)
			return fmt.Errorf("failed to process transaction: %w", err)
		}
		log.Printf("Transaction %d/%d processed successfully", i+1, len(transactions))
	}

	log.Printf("All %d transactions processed successfully", len(transactions))
	return nil
}

// ProcessTransaction processes a single transaction
func (bc *Blockchain) ProcessTransaction(tx *types.Transaction) error {
	log.Printf("Processing transaction: Type=%d, Nonce=%d, To=%s, Value=%s",
		tx.Type, tx.Nonce, tx.To.String(), tx.Value.String())

	// Get sender address
	sender, err := bc.getSenderAddress(tx)
	if err != nil {
		log.Printf("Failed to get sender address for transaction processing: %v", err)
		return fmt.Errorf("failed to get sender address: %w", err)
	}

	// Get sender account
	senderAccount, err := bc.stateMachines.GetAccount(sender)
	if err != nil {
		log.Printf("Failed to get sender account %s for transaction processing: %v", sender.String(), err)
		return fmt.Errorf("failed to get sender account: %w", err)
	}

	// Calculate total cost
	totalCost := new(big.Int).Add(tx.Value, tx.Fee)
	log.Printf("Transaction total cost: %s (value: %s + fee: %s)", totalCost.String(), tx.Value.String(), tx.Fee.String())

	// Update sender account
	oldBalance := senderAccount.Balance.String()
	senderAccount.Balance.Sub(senderAccount.Balance, totalCost)
	senderAccount.Nonce++

	log.Printf("Updated sender account %s: balance %s -> %s, nonce %d -> %d",
		sender.String(), oldBalance, senderAccount.Balance.String(), tx.Nonce, senderAccount.Nonce)

	// Store sender account
	err = bc.stateMachines.SetAccount(sender, senderAccount)
	if err != nil {
		log.Printf("Failed to store sender account %s: %v", sender.String(), err)
		return fmt.Errorf("failed to store sender account: %w", err)
	}

	// Process transaction based on type
	switch tx.Type {
	case types.TxTypeTransfer:
		log.Printf("Processing transfer transaction")
		// Update recipient account (if not zero address)
		if tx.To != (crypto.Address{}) {
			recipientAccount, err := bc.stateMachines.GetAccount(tx.To)
			if err != nil {
				log.Printf("Failed to get recipient account %s: %v", tx.To.String(), err)
				return fmt.Errorf("failed to get recipient account: %w", err)
			}

			oldRecipientBalance := recipientAccount.Balance.String()
			recipientAccount.Balance.Add(recipientAccount.Balance, tx.Value)
			log.Printf("Updated recipient account %s: balance %s -> %s",
				tx.To.String(), oldRecipientBalance, recipientAccount.Balance.String())

			err = bc.stateMachines.SetAccount(tx.To, recipientAccount)
			if err != nil {
				log.Printf("Failed to store recipient account %s: %v", tx.To.String(), err)
				return fmt.Errorf("failed to store recipient account: %w", err)
			}
		} else {
			log.Printf("Transfer to zero address (burn transaction)")
		}

	case types.TxTypeStake:
		log.Printf("Processing stake transaction for %s", sender.String())
		// Create or update validator
		validator, err := bc.stateMachines.GetValidator(sender)
		if err != nil {
			// Create new validator
			log.Printf("Creating new validator %s with stake %s", sender.String(), tx.Value.String())
			validator = &state.Validator{
				Address:        sender,
				SelfStake:      tx.Value,
				DelegatedStake: big.NewInt(0),
				Reputation:     1,
				IsOnline:       true,
				LastSeen:       time.Now().Unix(),
				Delegators:     make(map[crypto.Address]*big.Int),
				TotalRewards:   big.NewInt(0),
				BlocksProposed: 0,
				BlocksApproved: 0,
			}
		} else {
			// Update existing validator
			oldStake := validator.SelfStake.String()
			validator.SelfStake.Add(validator.SelfStake, tx.Value)
			validator.LastSeen = time.Now().Unix()
			log.Printf("Updated existing validator %s: self stake %s -> %s",
				sender.String(), oldStake, validator.SelfStake.String())
		}

		err = bc.stateMachines.SetValidator(sender, validator)
		if err != nil {
			log.Printf("Failed to update validator %s: %v", sender.String(), err)
			return fmt.Errorf("failed to update validator: %w", err)
		}

	case types.TxTypeUnstake:
		log.Printf("Processing unstake transaction for %s", sender.String())
		// Get validator
		validator, err := bc.stateMachines.GetValidator(sender)
		if err != nil {
			log.Printf("Validator %s not found for unstaking: %v", sender.String(), err)
			return fmt.Errorf("validator not found: %w", err)
		}

		// Check if enough stake to unstake
		if validator.SelfStake.Cmp(tx.Value) < 0 {
			log.Printf("Insufficient self stake to unstake: has %s, trying to unstake %s",
				validator.SelfStake.String(), tx.Value.String())
			return fmt.Errorf("insufficient self stake to unstake")
		}

		// Update validator
		oldStake := validator.SelfStake.String()
		validator.SelfStake.Sub(validator.SelfStake, tx.Value)
		validator.LastSeen = time.Now().Unix()
		log.Printf("Updated validator %s: self stake %s -> %s",
			sender.String(), oldStake, validator.SelfStake.String())

		// Update validator in state (even if stake becomes zero)
		err = bc.stateMachines.SetValidator(sender, validator)
		if err != nil {
			log.Printf("Failed to update validator %s: %v", sender.String(), err)
			return fmt.Errorf("failed to update validator: %w", err)
		}

	case types.TxTypeDelegate:
		log.Printf("Processing delegate transaction from %s to %s", sender.String(), tx.To.String())
		// Verify validator exists
		_, err := bc.stateMachines.GetValidator(tx.To)
		if err != nil {
			log.Printf("Validator %s not found for delegation: %v", tx.To.String(), err)
			return fmt.Errorf("validator not found: %w", err)
		}

		// Create or update delegation
		delegation, err := bc.stateMachines.GetDelegation(sender, tx.To)
		if err != nil {
			// Create new delegation
			log.Printf("Creating new delegation from %s to %s with amount %s",
				sender.String(), tx.To.String(), tx.Value.String())
			delegation = &types.Delegation{
				Delegator:   sender,
				Validator:   tx.To,
				Amount:      tx.Value,
				Rewards:     big.NewInt(0),
				LastClaimed: time.Now().Unix(),
			}
		} else {
			// Update existing delegation
			oldAmount := delegation.Amount.String()
			delegation.Amount.Add(delegation.Amount, tx.Value)
			log.Printf("Updated existing delegation from %s to %s: amount %s -> %s",
				sender.String(), tx.To.String(), oldAmount, delegation.Amount.String())
		}

		err = bc.stateMachines.SetDelegation(delegation)
		if err != nil {
			log.Printf("Failed to set delegation: %v", err)
			return fmt.Errorf("failed to set delegation: %w", err)
		}

	case types.TxTypeUndelegate:
		log.Printf("Processing undelegate transaction from %s to %s", sender.String(), tx.To.String())
		// Get delegation
		delegation, err := bc.stateMachines.GetDelegation(sender, tx.To)
		if err != nil {
			log.Printf("Delegation from %s to %s not found: %v", sender.String(), tx.To.String(), err)
			return fmt.Errorf("delegation not found: %w", err)
		}

		// Check if enough delegated amount
		if delegation.Amount.Cmp(tx.Value) < 0 {
			log.Printf("Insufficient delegated amount to undelegate: has %s, trying to undelegate %s",
				delegation.Amount.String(), tx.Value.String())
			return fmt.Errorf("insufficient delegated amount to undelegate")
		}

		// Update delegation
		oldAmount := delegation.Amount.String()
		delegation.Amount.Sub(delegation.Amount, tx.Value)
		log.Printf("Updated delegation from %s to %s: amount %s -> %s",
			sender.String(), tx.To.String(), oldAmount, delegation.Amount.String())

		if delegation.Amount.Cmp(big.NewInt(0)) == 0 {
			// Remove delegation if amount becomes zero
			log.Printf("Removing delegation from %s to %s (amount became zero)", sender.String(), tx.To.String())
			err = bc.stateMachines.RemoveDelegation(sender, tx.To)
			if err != nil {
				log.Printf("Failed to remove delegation: %v", err)
				return fmt.Errorf("failed to remove delegation: %w", err)
			}
		} else {
			err = bc.stateMachines.SetDelegation(delegation)
			if err != nil {
				log.Printf("Failed to update delegation: %v", err)
				return fmt.Errorf("failed to update delegation: %w", err)
			}
		}

	case types.TxTypeClaimRewards:
		log.Printf("Processing claim rewards transaction from %s to %s", sender.String(), tx.To.String())
		// Get delegation
		delegation, err := bc.stateMachines.GetDelegation(sender, tx.To)
		if err != nil {
			log.Printf("Delegation from %s to %s not found for claiming rewards: %v", sender.String(), tx.To.String(), err)
			return fmt.Errorf("delegation not found: %w", err)
		}

		// Calculate rewards (simplified - in practice this would be more complex)
		rewards := delegation.Rewards
		if rewards.Cmp(big.NewInt(0)) > 0 {
			log.Printf("Claiming rewards %s for delegation from %s to %s",
				rewards.String(), sender.String(), tx.To.String())

			// Transfer rewards to delegator
			oldBalance := senderAccount.Balance.String()
			senderAccount.Balance.Add(senderAccount.Balance, rewards)
			log.Printf("Updated sender account %s: balance %s -> %s (added rewards)",
				sender.String(), oldBalance, senderAccount.Balance.String())

			err = bc.stateMachines.SetAccount(sender, senderAccount)
			if err != nil {
				log.Printf("Failed to update sender account %s: %v", sender.String(), err)
				return fmt.Errorf("failed to update sender account: %w", err)
			}

			// Reset delegation rewards
			delegation.Rewards = big.NewInt(0)
			delegation.LastClaimed = time.Now().Unix()
			log.Printf("Reset rewards for delegation from %s to %s", sender.String(), tx.To.String())

			err = bc.stateMachines.SetDelegation(delegation)
			if err != nil {
				log.Printf("Failed to update delegation: %v", err)
				return fmt.Errorf("failed to update delegation: %w", err)
			}
		} else {
			log.Printf("No rewards to claim for delegation from %s to %s", sender.String(), tx.To.String())
		}
	}

	log.Printf("Transaction processing completed successfully")
	return nil
}

// getSenderAddress extracts the sender address from a transaction
func (bc *Blockchain) getSenderAddress(tx *types.Transaction) (crypto.Address, error) {
	// Recreate transaction without signature
	txCopy := *tx
	txCopy.Signature = types.Signature{}
	txHash := txCopy.Hash()

	// Recover public key
	pubKey, err := crypto.Ecrecover(txHash[:], append(tx.Signature.R[:], tx.Signature.S[:]...), tx.Signature.V)
	if err != nil {
		return crypto.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}

	// Derive address
	address := crypto.PubToAddress(pubKey)
	return address, nil
}

// calculateTxRoot calculates the transaction root
func (bc *Blockchain) calculateTxRoot(transactions []types.Transaction) crypto.Hash {
	if len(transactions) == 0 {
		return crypto.Hash{}
	}

	// Simple concatenation and hashing
	var data []byte
	for _, tx := range transactions {
		hash := tx.Hash()
		data = append(data, hash[:]...)
	}

	return crypto.CalculateHash(data)
}

// GetGenesisBlock returns the genesis block
func (bc *Blockchain) GetGenesisBlock() (*types.Block, error) {
	return bc.storage.GetGenesis()
}

// GetLatestBlock returns the latest block
func (bc *Blockchain) GetLatestBlock() (*types.Block, error) {
	// If latest is 0, try to get genesis block
	if bc.latest == 0 {
		return bc.storage.GetGenesis()
	}
	return bc.storage.GetBlockByHeight(bc.latest)
}

// GetBlockByHeight returns a block by height
func (bc *Blockchain) GetBlockByHeight(height uint64) (*types.Block, error) {
	return bc.storage.GetBlockByHeight(height)
}

// GetBlockByHash returns a block by hash
func (bc *Blockchain) GetBlockByHash(hash crypto.Hash) (*types.Block, error) {
	return bc.storage.GetBlockByHash(hash)
}

// GetTransaction returns a transaction by hash
func (bc *Blockchain) GetTransaction(hash crypto.Hash) (*types.Transaction, error) {
	return bc.stateMachines.GetTransaction(hash)
}

// GetAccount returns an account by address
func (bc *Blockchain) GetAccount(address crypto.Address) (*state.Account, error) {
	return bc.stateMachines.GetAccount(address)
}

// GetValidator returns a validator by address
func (bc *Blockchain) GetValidator(address crypto.Address) (*state.Validator, error) {
	return bc.stateMachines.GetValidator(address)
}

// GetAllValidators returns all validators
func (bc *Blockchain) GetAllValidators() ([]*state.Validator, error) {
	return bc.stateMachines.GetAllValidators()
}

// GetLatestHeight returns the latest block height
func (bc *Blockchain) GetLatestHeight() uint64 {
	return bc.latest
}

// GetStateRoots returns the current state roots
func (bc *Blockchain) GetStateRoots() (crypto.Hash, crypto.Hash, crypto.Hash) {
	return bc.stateMachines.GetStateRoots()
}

// SetAccount sets an account in the state machine (for testing purposes)
func (bc *Blockchain) SetAccount(address crypto.Address, account *state.Account) error {
	return bc.stateMachines.SetAccount(address, account)
}

// CalculateTxRoot calculates the transaction root for a list of transactions
func (bc *Blockchain) CalculateTxRoot(transactions []types.Transaction) crypto.Hash {
	return bc.calculateTxRoot(transactions)
}
