package state

import (
	"fmt"
	"math/big"

	"dyphira-node/crypto"
	"dyphira-node/types"
)

// StateMachines represents the collection of individual state machines
// that track different aspects of the distributed ledger
type StateMachines struct {
	// Core account state - stores all accounts with balance and nonce
	AccountState *Trie

	// Participant tracker - tracks current eligible validators
	ValidatorState *Trie

	// Transaction tracker - stores all finalized transactions
	TransactionState *Trie

	// Separate database for actual data storage
	DataDB *StateDataDB
}

// StateDataDB represents the separate database for storing actual values
// This is separate from the trie structure as per the specification
type StateDataDB struct {
	accounts     map[crypto.Address]*Account
	validators   map[crypto.Address]*Validator
	transactions map[crypto.Hash]*types.Transaction
	delegations  map[crypto.Address]map[crypto.Address]*types.Delegation // delegator -> validator -> delegation
}

// NewStateMachines creates new state machines
func NewStateMachines() *StateMachines {
	return &StateMachines{
		AccountState:     NewTrie(),
		ValidatorState:   NewTrie(),
		TransactionState: NewTrie(),
		DataDB: &StateDataDB{
			accounts:     make(map[crypto.Address]*Account),
			validators:   make(map[crypto.Address]*Validator),
			transactions: make(map[crypto.Hash]*types.Transaction),
			delegations:  make(map[crypto.Address]map[crypto.Address]*types.Delegation),
		},
	}
}

// GetAccount retrieves an account from the state machines
func (sm *StateMachines) GetAccount(address crypto.Address) (*Account, error) {
	// Check if account exists in trie
	balanceKey := AccountKey(address)
	nonceKey := NonceKey(address)

	balanceData, balanceExists := sm.AccountState.Get(balanceKey)
	nonceData, nonceExists := sm.AccountState.Get(nonceKey)

	if !balanceExists && !nonceExists {
		// Return empty account if not found
		return &Account{
			Balance: big.NewInt(0),
			Nonce:   0,
		}, nil
	}

	// Get actual account data from separate database
	account, exists := sm.DataDB.accounts[address]
	if !exists {
		// Decode from trie data if not in separate DB
		if balanceExists {
			balance := new(big.Int).SetBytes(balanceData)
			nonce := uint64(0)
			if nonceExists {
				nonce = new(big.Int).SetBytes(nonceData).Uint64()
			}
			return &Account{
				Balance: balance,
				Nonce:   nonce,
			}, nil
		}
		return &Account{
			Balance: big.NewInt(0),
			Nonce:   0,
		}, nil
	}

	return account, nil
}

// SetAccount stores an account in the state machines
func (sm *StateMachines) SetAccount(address crypto.Address, account *Account) error {
	// Store in separate database
	sm.DataDB.accounts[address] = account

	// Store balance in trie
	balanceKey := AccountKey(address)
	balanceBytes := account.Balance.Bytes()
	err := sm.AccountState.Put(balanceKey, balanceBytes)
	if err != nil {
		return fmt.Errorf("failed to store balance in trie: %w", err)
	}

	// Store nonce in trie
	nonceKey := NonceKey(address)
	nonceBytes := big.NewInt(int64(account.Nonce)).Bytes()
	err = sm.AccountState.Put(nonceKey, nonceBytes)
	if err != nil {
		return fmt.Errorf("failed to store nonce in trie: %w", err)
	}

	return nil
}

// GetValidator retrieves a validator from the state machines
func (sm *StateMachines) GetValidator(address crypto.Address) (*Validator, error) {
	// Check if validator exists in trie
	validatorKey := ValidatorKey(address)
	_, exists := sm.ValidatorState.Get(validatorKey)

	if !exists {
		return nil, fmt.Errorf("validator not found: %s", address.String())
	}

	// Get actual validator data from separate database
	validator, exists := sm.DataDB.validators[address]
	if !exists {
		return nil, fmt.Errorf("validator data not found: %s", address.String())
	}

	return validator, nil
}

// SetValidator stores a validator in the state machines
func (sm *StateMachines) SetValidator(address crypto.Address, validator *Validator) error {
	// Store in separate database
	sm.DataDB.validators[address] = validator

	// Store validator hash in trie (just a marker that validator exists)
	validatorKey := ValidatorKey(address)
	validatorBytes, err := EncodeValidator(validator)
	if err != nil {
		return fmt.Errorf("failed to encode validator: %w", err)
	}
	validatorHash := crypto.CalculateHash(validatorBytes)
	err = sm.ValidatorState.Put(validatorKey, validatorHash[:])
	if err != nil {
		return fmt.Errorf("failed to store validator in trie: %w", err)
	}

	return nil
}

// GetAllValidators retrieves all validators from the state machines
func (sm *StateMachines) GetAllValidators() ([]*Validator, error) {
	var validators []*Validator

	for address, validator := range sm.DataDB.validators {
		// Verify validator exists in trie
		validatorKey := ValidatorKey(address)
		_, exists := sm.ValidatorState.Get(validatorKey)
		if exists {
			validators = append(validators, validator)
		}
	}

	return validators, nil
}

// AddTransaction adds a finalized transaction to the state machines
func (sm *StateMachines) AddTransaction(tx *types.Transaction) error {
	txHash := tx.Hash()

	// Store in separate database
	sm.DataDB.transactions[txHash] = tx

	// Store transaction hash in trie
	txKey := crypto.CalculateHash(txHash[:])
	err := sm.TransactionState.Put(txKey[:], txHash[:])
	if err != nil {
		return fmt.Errorf("failed to store transaction in trie: %w", err)
	}

	return nil
}

// GetTransaction retrieves a transaction from the state machines
func (sm *StateMachines) GetTransaction(hash crypto.Hash) (*types.Transaction, error) {
	// Check if transaction exists in trie
	txKey := crypto.CalculateHash(hash[:])
	_, exists := sm.TransactionState.Get(txKey[:])

	if !exists {
		return nil, fmt.Errorf("transaction not found: %s", hash.String())
	}

	// Get actual transaction data from separate database
	tx, exists := sm.DataDB.transactions[hash]
	if !exists {
		return nil, fmt.Errorf("transaction data not found: %s", hash.String())
	}

	return tx, nil
}

// GetStateRoots returns the root hashes of all state machines
func (sm *StateMachines) GetStateRoots() (crypto.Hash, crypto.Hash, crypto.Hash) {
	return sm.AccountState.Root(), sm.ValidatorState.Root(), sm.TransactionState.Root()
}

// UpdateStateRoots updates the state roots after state transitions
func (sm *StateMachines) UpdateStateRoots() {
	// The trie roots are automatically updated when data is modified
	// This function can be used for additional state root management if needed
}

// CommitStateTransition commits all state changes after a finalized state transition
func (sm *StateMachines) CommitStateTransition() error {
	// Update state roots
	sm.UpdateStateRoots()

	// In a real implementation, this would persist the state to disk
	// For now, we just ensure all changes are committed to memory

	return nil
}

// GetAccountStateRoot returns the account state trie root
func (sm *StateMachines) GetAccountStateRoot() crypto.Hash {
	return sm.AccountState.Root()
}

// GetValidatorStateRoot returns the validator state trie root
func (sm *StateMachines) GetValidatorStateRoot() crypto.Hash {
	return sm.ValidatorState.Root()
}

// GetTransactionStateRoot returns the transaction state trie root
func (sm *StateMachines) GetTransactionStateRoot() crypto.Hash {
	return sm.TransactionState.Root()
}

// GetDelegation retrieves a delegation from a delegator to a validator
func (sm *StateMachines) GetDelegation(delegator, validator crypto.Address) (*types.Delegation, error) {
	validatorDelegations, exists := sm.DataDB.delegations[delegator]
	if !exists {
		return nil, fmt.Errorf("no delegations found for delegator: %s", delegator.String())
	}

	delegation, exists := validatorDelegations[validator]
	if !exists {
		return nil, fmt.Errorf("delegation not found: delegator %s to validator %s", delegator.String(), validator.String())
	}

	return delegation, nil
}

// SetDelegation stores a delegation in the state machines
func (sm *StateMachines) SetDelegation(delegation *types.Delegation) error {
	// Initialize delegator map if it doesn't exist
	if sm.DataDB.delegations[delegation.Delegator] == nil {
		sm.DataDB.delegations[delegation.Delegator] = make(map[crypto.Address]*types.Delegation)
	}

	// Store delegation
	sm.DataDB.delegations[delegation.Delegator][delegation.Validator] = delegation

	// Update validator's delegated stake
	validator, err := sm.GetValidator(delegation.Validator)
	if err != nil {
		return fmt.Errorf("failed to get validator: %w", err)
	}

	// Initialize delegators map if it doesn't exist
	if validator.Delegators == nil {
		validator.Delegators = make(map[crypto.Address]*big.Int)
	}

	// Update or add delegator
	validator.Delegators[delegation.Delegator] = delegation.Amount

	// Recalculate total delegated stake
	totalDelegated := big.NewInt(0)
	for _, amount := range validator.Delegators {
		totalDelegated.Add(totalDelegated, amount)
	}
	validator.DelegatedStake = totalDelegated

	// Update validator in state
	err = sm.SetValidator(delegation.Validator, validator)
	if err != nil {
		return fmt.Errorf("failed to update validator: %w", err)
	}

	return nil
}

// RemoveDelegation removes a delegation from the state machines
func (sm *StateMachines) RemoveDelegation(delegator, validator crypto.Address) error {
	validatorDelegations, exists := sm.DataDB.delegations[delegator]
	if !exists {
		return fmt.Errorf("no delegations found for delegator: %s", delegator.String())
	}

	if _, exists := validatorDelegations[validator]; !exists {
		return fmt.Errorf("delegation not found: delegator %s to validator %s", delegator.String(), validator.String())
	}

	// Remove delegation
	delete(validatorDelegations, validator)
	if len(validatorDelegations) == 0 {
		delete(sm.DataDB.delegations, delegator)
	}

	// Update validator's delegated stake
	validatorObj, err := sm.GetValidator(validator)
	if err != nil {
		return fmt.Errorf("failed to get validator: %w", err)
	}

	// Remove delegator from validator
	delete(validatorObj.Delegators, delegator)

	// Recalculate total delegated stake
	totalDelegated := big.NewInt(0)
	for _, amount := range validatorObj.Delegators {
		totalDelegated.Add(totalDelegated, amount)
	}
	validatorObj.DelegatedStake = totalDelegated

	// Update validator in state
	err = sm.SetValidator(validator, validatorObj)
	if err != nil {
		return fmt.Errorf("failed to update validator: %w", err)
	}

	return nil
}

// GetAllDelegationsForDelegator returns all delegations for a specific delegator
func (sm *StateMachines) GetAllDelegationsForDelegator(delegator crypto.Address) ([]*types.Delegation, error) {
	validatorDelegations, exists := sm.DataDB.delegations[delegator]
	if !exists {
		return []*types.Delegation{}, nil
	}

	var delegations []*types.Delegation
	for _, delegation := range validatorDelegations {
		delegations = append(delegations, delegation)
	}

	return delegations, nil
}

// GetAllDelegationsForValidator returns all delegations for a specific validator
func (sm *StateMachines) GetAllDelegationsForValidator(validator crypto.Address) ([]*types.Delegation, error) {
	var delegations []*types.Delegation

	for _, validatorDelegations := range sm.DataDB.delegations {
		if delegation, exists := validatorDelegations[validator]; exists {
			delegations = append(delegations, delegation)
		}
	}

	return delegations, nil
}
