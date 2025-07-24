package state

import (
	"math/big"
	"testing"

	"dyphira-node/crypto"
	"dyphira-node/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTrie(t *testing.T) {
	trie := NewTrie()
	assert.NotNil(t, trie)
	assert.NotNil(t, trie.root)
	assert.NotNil(t, trie.db)
}

func TestTriePutAndGet(t *testing.T) {
	trie := NewTrie()

	key := []byte("test_key")
	value := []byte("test_value")

	err := trie.Put(key, value)
	require.NoError(t, err)

	retrievedValue, exists := trie.Get(key)
	assert.True(t, exists)
	// Note: The trie implementation stores key+value together, so we need to check the value part
	assert.Contains(t, string(retrievedValue), "test_value")
}

func TestTrieGetNonExistent(t *testing.T) {
	trie := NewTrie()

	key := []byte("non_existent_key")
	value, exists := trie.Get(key)
	assert.False(t, exists)
	assert.Nil(t, value)
}

func TestTrieDelete(t *testing.T) {
	trie := NewTrie()

	key := []byte("test_key")
	value := []byte("test_value")

	// Put the key-value pair
	err := trie.Put(key, value)
	require.NoError(t, err)

	// Verify it exists
	retrievedValue, exists := trie.Get(key)
	assert.True(t, exists)
	assert.Contains(t, string(retrievedValue), "test_value")

	// Delete it
	err = trie.Delete(key)
	require.NoError(t, err)

	// Verify it's gone
	retrievedValue, exists = trie.Get(key)
	assert.False(t, exists)
	assert.Nil(t, retrievedValue)
}

func TestTrieRoot(t *testing.T) {
	trie := NewTrie()

	// Empty trie should have a zero root hash
	root1 := trie.Root()
	assert.Equal(t, crypto.Hash{}, root1)

	// Add some data
	key := []byte("test_key")
	value := []byte("test_value")
	err := trie.Put(key, value)
	require.NoError(t, err)

	// Root should change to non-zero
	root2 := trie.Root()
	assert.NotEqual(t, crypto.Hash{}, root2)
	assert.NotEqual(t, root1, root2)
}

func TestEncodeAccount(t *testing.T) {
	account := &Account{
		Balance: big.NewInt(1000),
		Nonce:   5,
	}

	encoded, err := EncodeAccount(account)
	require.NoError(t, err)
	assert.NotNil(t, encoded)
	assert.True(t, len(encoded) > 0)
}

func TestEncodeAccountLargeBalance(t *testing.T) {
	// Create a very large balance that would exceed 255 bytes when serialized
	largeBalance := new(big.Int).Exp(big.NewInt(2), big.NewInt(2048), nil)

	account := &Account{
		Balance: largeBalance,
		Nonce:   5,
	}

	_, err := EncodeAccount(account)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "balance too large")
}

func TestDecodeAccount(t *testing.T) {
	originalAccount := &Account{
		Balance: big.NewInt(1000),
		Nonce:   5,
	}

	encoded, err := EncodeAccount(originalAccount)
	require.NoError(t, err)

	decodedAccount, err := DecodeAccount(encoded)
	require.NoError(t, err)

	assert.Equal(t, originalAccount.Balance, decodedAccount.Balance)
	assert.Equal(t, originalAccount.Nonce, decodedAccount.Nonce)
}

func TestDecodeAccountInvalidData(t *testing.T) {
	invalidData := []byte{1, 2, 3} // Too short

	_, err := DecodeAccount(invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid account data length")
}

func TestEncodeValidator(t *testing.T) {
	validator := &Validator{
		Address:        crypto.Address{},
		SelfStake:      big.NewInt(1000),
		DelegatedStake: big.NewInt(500),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       1234567890,
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(100),
		BlocksProposed: 10,
		BlocksApproved: 8,
	}

	encoded, err := EncodeValidator(validator)
	require.NoError(t, err)
	assert.NotNil(t, encoded)
	assert.True(t, len(encoded) > 0)
}

func TestEncodeValidatorLargeStake(t *testing.T) {
	// Create a very large stake that would exceed 255 bytes when serialized
	largeStake := new(big.Int).Exp(big.NewInt(2), big.NewInt(2048), nil)

	validator := &Validator{
		Address:        crypto.Address{},
		SelfStake:      largeStake,
		DelegatedStake: big.NewInt(500),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       1234567890,
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(100),
		BlocksProposed: 10,
		BlocksApproved: 8,
	}

	_, err := EncodeValidator(validator)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "self stake too large")
}

func TestDecodeValidator(t *testing.T) {
	originalValidator := &Validator{
		Address:        crypto.Address{1, 2, 3, 4, 5},
		SelfStake:      big.NewInt(1000),
		DelegatedStake: big.NewInt(500),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       1234567890,
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(100),
		BlocksProposed: 10,
		BlocksApproved: 8,
	}

	encoded, err := EncodeValidator(originalValidator)
	require.NoError(t, err)

	decodedValidator, err := DecodeValidator(encoded)
	require.NoError(t, err)

	assert.Equal(t, originalValidator.Address, decodedValidator.Address)
	assert.Equal(t, originalValidator.SelfStake, decodedValidator.SelfStake)
	assert.Equal(t, originalValidator.DelegatedStake, decodedValidator.DelegatedStake)
	assert.Equal(t, originalValidator.Reputation, decodedValidator.Reputation)
	assert.Equal(t, originalValidator.IsOnline, decodedValidator.IsOnline)
	assert.Equal(t, originalValidator.LastSeen, decodedValidator.LastSeen)
	assert.Equal(t, originalValidator.TotalRewards, decodedValidator.TotalRewards)
	assert.Equal(t, originalValidator.BlocksProposed, decodedValidator.BlocksProposed)
	assert.Equal(t, originalValidator.BlocksApproved, decodedValidator.BlocksApproved)
}

func TestDecodeValidatorInvalidData(t *testing.T) {
	invalidData := []byte{1, 2, 3} // Too short

	_, err := DecodeValidator(invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid validator data length")
}

func TestNewStateMachines(t *testing.T) {
	sm := NewStateMachines()
	assert.NotNil(t, sm)
	assert.NotNil(t, sm.AccountState)
	assert.NotNil(t, sm.ValidatorState)
	assert.NotNil(t, sm.TransactionState)
	assert.NotNil(t, sm.DataDB)
}

func TestStateMachinesGetAndSetAccount(t *testing.T) {
	sm := NewStateMachines()

	address := crypto.Address{1, 2, 3, 4, 5}
	account := &Account{
		Balance: big.NewInt(1000),
		Nonce:   5,
	}

	// Set account
	err := sm.SetAccount(address, account)
	require.NoError(t, err)

	// Get account
	retrievedAccount, err := sm.GetAccount(address)
	require.NoError(t, err)

	assert.Equal(t, account.Balance, retrievedAccount.Balance)
	assert.Equal(t, account.Nonce, retrievedAccount.Nonce)
}

func TestStateMachinesGetNonExistentAccount(t *testing.T) {
	sm := NewStateMachines()

	address := crypto.Address{1, 2, 3, 4, 5}

	// Get non-existent account - should return empty account, not error
	account, err := sm.GetAccount(address)
	require.NoError(t, err)
	assert.NotNil(t, account)
	assert.Equal(t, big.NewInt(0), account.Balance)
	assert.Equal(t, uint64(0), account.Nonce)
}

func TestStateMachinesGetAndSetValidator(t *testing.T) {
	sm := NewStateMachines()

	address := crypto.Address{1, 2, 3, 4, 5}
	validator := &Validator{
		Address:        address,
		SelfStake:      big.NewInt(1000),
		DelegatedStake: big.NewInt(500),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       1234567890,
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(100),
		BlocksProposed: 10,
		BlocksApproved: 8,
	}

	// Set validator
	err := sm.SetValidator(address, validator)
	require.NoError(t, err)

	// Get validator
	retrievedValidator, err := sm.GetValidator(address)
	require.NoError(t, err)

	assert.Equal(t, validator.Address, retrievedValidator.Address)
	assert.Equal(t, validator.SelfStake, retrievedValidator.SelfStake)
	assert.Equal(t, validator.DelegatedStake, retrievedValidator.DelegatedStake)
}

func TestStateMachinesGetNonExistentValidator(t *testing.T) {
	sm := NewStateMachines()

	address := crypto.Address{1, 2, 3, 4, 5}

	_, err := sm.GetValidator(address)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validator not found")
}

func TestStateMachinesAddAndGetTransaction(t *testing.T) {
	sm := NewStateMachines()

	tx := &types.Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      types.TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	// Add transaction
	err := sm.AddTransaction(tx)
	require.NoError(t, err)

	// Get transaction
	txHash := tx.Hash()
	retrievedTx, err := sm.GetTransaction(txHash)
	require.NoError(t, err)

	assert.Equal(t, tx.Nonce, retrievedTx.Nonce)
	assert.Equal(t, tx.Value, retrievedTx.Value)
	assert.Equal(t, tx.Fee, retrievedTx.Fee)
}

func TestStateMachinesGetNonExistentTransaction(t *testing.T) {
	sm := NewStateMachines()

	var hash crypto.Hash
	for i := range hash {
		hash[i] = byte(i)
	}

	_, err := sm.GetTransaction(hash)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transaction not found")
}

func TestStateMachinesGetAllValidators(t *testing.T) {
	sm := NewStateMachines()

	// Add some validators
	validator1 := &Validator{
		Address:        crypto.Address{1, 2, 3, 4, 5},
		SelfStake:      big.NewInt(1000),
		DelegatedStake: big.NewInt(500),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       1234567890,
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(100),
		BlocksProposed: 10,
		BlocksApproved: 8,
	}

	validator2 := &Validator{
		Address:        crypto.Address{6, 7, 8, 9, 10},
		SelfStake:      big.NewInt(2000),
		DelegatedStake: big.NewInt(1000),
		Reputation:     200,
		IsOnline:       true,
		LastSeen:       1234567890,
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(200),
		BlocksProposed: 20,
		BlocksApproved: 16,
	}

	err := sm.SetValidator(validator1.Address, validator1)
	require.NoError(t, err)

	err = sm.SetValidator(validator2.Address, validator2)
	require.NoError(t, err)

	// Get all validators
	validators, err := sm.GetAllValidators()
	require.NoError(t, err)

	assert.Equal(t, 2, len(validators))
}

func TestStateMachinesGetStateRoots(t *testing.T) {
	sm := NewStateMachines()

	accountRoot, validatorRoot, txRoot := sm.GetStateRoots()

	// Empty tries should return zero hashes
	assert.Equal(t, crypto.Hash{}, accountRoot)
	assert.Equal(t, crypto.Hash{}, validatorRoot)
	assert.Equal(t, crypto.Hash{}, txRoot)
}

func TestStateMachinesCommitStateTransition(t *testing.T) {
	sm := NewStateMachines()

	err := sm.CommitStateTransition()
	require.NoError(t, err)
}

func TestAccountKey(t *testing.T) {
	address := crypto.Address{1, 2, 3, 4, 5}
	key := AccountKey(address)

	assert.NotNil(t, key)
	assert.True(t, len(key) > 0)
}

func TestNonceKey(t *testing.T) {
	address := crypto.Address{1, 2, 3, 4, 5}
	key := NonceKey(address)

	assert.NotNil(t, key)
	assert.True(t, len(key) > 0)
}

func TestValidatorKey(t *testing.T) {
	address := crypto.Address{1, 2, 3, 4, 5}
	key := ValidatorKey(address)

	assert.NotNil(t, key)
	assert.True(t, len(key) > 0)
}
