package core

import (
	"fmt"
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
	// Check block height
	if block.Header.Height != bc.latest+1 {
		return fmt.Errorf("invalid block height: expected %d, got %d", bc.latest+1, block.Header.Height)
	}

	// Check previous hash
	latestBlock, err := bc.GetLatestBlock()
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}
	if block.Header.PrevHash != latestBlock.Hash() {
		return fmt.Errorf("invalid previous hash")
	}

	// Validate transactions
	for _, tx := range block.Transactions {
		err := bc.ValidateTransaction(&tx)
		if err != nil {
			return fmt.Errorf("invalid transaction: %w", err)
		}
	}

	// Check transaction root
	expectedTxRoot := bc.calculateTxRoot(block.Transactions)
	if block.Header.TxRoot != expectedTxRoot {
		return fmt.Errorf("invalid transaction root")
	}

	return nil
}

// ValidateTransaction validates a transaction
func (bc *Blockchain) ValidateTransaction(tx *types.Transaction) error {
	// Check transaction signature
	if !tx.Verify() {
		return fmt.Errorf("invalid transaction signature")
	}

	// Get sender account
	sender, err := bc.getSenderAddress(tx)
	if err != nil {
		return fmt.Errorf("failed to get sender address: %w", err)
	}

	account, err := bc.stateMachines.GetAccount(sender)
	if err != nil {
		return fmt.Errorf("failed to get sender account: %w", err)
	}

	// Check nonce
	if tx.Nonce != account.Nonce {
		return fmt.Errorf("invalid nonce: expected %d, got %d", account.Nonce, tx.Nonce)
	}

	// Check balance
	totalCost := new(big.Int).Add(tx.Value, tx.Fee)
	if account.Balance.Cmp(totalCost) < 0 {
		return fmt.Errorf("insufficient balance")
	}

	// Check value and fee are positive
	if tx.Value.Cmp(big.NewInt(0)) < 0 {
		return fmt.Errorf("negative value")
	}
	if tx.Fee.Cmp(big.NewInt(0)) < 0 {
		return fmt.Errorf("negative fee")
	}

	return nil
}

// ProcessTransactions processes a list of transactions
func (bc *Blockchain) ProcessTransactions(transactions []types.Transaction) error {
	for _, tx := range transactions {
		err := bc.ProcessTransaction(&tx)
		if err != nil {
			return fmt.Errorf("failed to process transaction: %w", err)
		}
	}
	return nil
}

// ProcessTransaction processes a single transaction
func (bc *Blockchain) ProcessTransaction(tx *types.Transaction) error {
	// Get sender address
	sender, err := bc.getSenderAddress(tx)
	if err != nil {
		return fmt.Errorf("failed to get sender address: %w", err)
	}

	// Get sender account
	senderAccount, err := bc.stateMachines.GetAccount(sender)
	if err != nil {
		return fmt.Errorf("failed to get sender account: %w", err)
	}

	// Calculate total cost
	totalCost := new(big.Int).Add(tx.Value, tx.Fee)

	// Update sender account
	senderAccount.Balance.Sub(senderAccount.Balance, totalCost)
	senderAccount.Nonce++

	// Store sender account
	err = bc.stateMachines.SetAccount(sender, senderAccount)
	if err != nil {
		return fmt.Errorf("failed to store sender account: %w", err)
	}

	// Process transaction based on type
	switch tx.Type {
	case types.TxTypeTransfer:
		// Update recipient account (if not zero address)
		if tx.To != (crypto.Address{}) {
			recipientAccount, err := bc.stateMachines.GetAccount(tx.To)
			if err != nil {
				return fmt.Errorf("failed to get recipient account: %w", err)
			}

			recipientAccount.Balance.Add(recipientAccount.Balance, tx.Value)

			err = bc.stateMachines.SetAccount(tx.To, recipientAccount)
			if err != nil {
				return fmt.Errorf("failed to store recipient account: %w", err)
			}
		}

	case types.TxTypeStake:
		// Create or update validator
		validator, err := bc.stateMachines.GetValidator(sender)
		if err != nil {
			// Create new validator
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
			validator.SelfStake.Add(validator.SelfStake, tx.Value)
			validator.LastSeen = time.Now().Unix()
		}

		err = bc.stateMachines.SetValidator(sender, validator)
		if err != nil {
			return fmt.Errorf("failed to update validator: %w", err)
		}

	case types.TxTypeUnstake:
		// Get validator
		validator, err := bc.stateMachines.GetValidator(sender)
		if err != nil {
			return fmt.Errorf("validator not found: %w", err)
		}

		// Check if enough stake to unstake
		if validator.SelfStake.Cmp(tx.Value) < 0 {
			return fmt.Errorf("insufficient self stake to unstake")
		}

		// Update validator
		validator.SelfStake.Sub(validator.SelfStake, tx.Value)
		validator.LastSeen = time.Now().Unix()

		// Update validator in state (even if stake becomes zero)
		err = bc.stateMachines.SetValidator(sender, validator)
		if err != nil {
			return fmt.Errorf("failed to update validator: %w", err)
		}

	case types.TxTypeDelegate:
		// Verify validator exists
		_, err := bc.stateMachines.GetValidator(tx.To)
		if err != nil {
			return fmt.Errorf("validator not found: %w", err)
		}

		// Create or update delegation
		delegation, err := bc.stateMachines.GetDelegation(sender, tx.To)
		if err != nil {
			// Create new delegation
			delegation = &types.Delegation{
				Delegator:   sender,
				Validator:   tx.To,
				Amount:      tx.Value,
				Rewards:     big.NewInt(0),
				LastClaimed: time.Now().Unix(),
			}
		} else {
			// Update existing delegation
			delegation.Amount.Add(delegation.Amount, tx.Value)
		}

		err = bc.stateMachines.SetDelegation(delegation)
		if err != nil {
			return fmt.Errorf("failed to set delegation: %w", err)
		}

	case types.TxTypeUndelegate:
		// Get delegation
		delegation, err := bc.stateMachines.GetDelegation(sender, tx.To)
		if err != nil {
			return fmt.Errorf("delegation not found: %w", err)
		}

		// Check if enough delegated amount
		if delegation.Amount.Cmp(tx.Value) < 0 {
			return fmt.Errorf("insufficient delegated amount to undelegate")
		}

		// Update delegation
		delegation.Amount.Sub(delegation.Amount, tx.Value)

		if delegation.Amount.Cmp(big.NewInt(0)) == 0 {
			// Remove delegation if amount becomes zero
			err = bc.stateMachines.RemoveDelegation(sender, tx.To)
			if err != nil {
				return fmt.Errorf("failed to remove delegation: %w", err)
			}
		} else {
			err = bc.stateMachines.SetDelegation(delegation)
			if err != nil {
				return fmt.Errorf("failed to update delegation: %w", err)
			}
		}

	case types.TxTypeClaimRewards:
		// Get delegation
		delegation, err := bc.stateMachines.GetDelegation(sender, tx.To)
		if err != nil {
			return fmt.Errorf("delegation not found: %w", err)
		}

		// Calculate rewards (simplified - in practice this would be more complex)
		rewards := delegation.Rewards
		if rewards.Cmp(big.NewInt(0)) > 0 {
			// Transfer rewards to delegator
			senderAccount.Balance.Add(senderAccount.Balance, rewards)
			err = bc.stateMachines.SetAccount(sender, senderAccount)
			if err != nil {
				return fmt.Errorf("failed to update sender account: %w", err)
			}

			// Reset delegation rewards
			delegation.Rewards = big.NewInt(0)
			delegation.LastClaimed = time.Now().Unix()

			err = bc.stateMachines.SetDelegation(delegation)
			if err != nil {
				return fmt.Errorf("failed to update delegation: %w", err)
			}
		}
	}

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
