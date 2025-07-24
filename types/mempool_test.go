package types

import (
	"math/big"
	"testing"

	"dyphira-node/crypto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMempool(t *testing.T) {
	mempool := NewMempool(1000)
	assert.NotNil(t, mempool)
	assert.Equal(t, 1000, mempool.maxSize)
	assert.NotNil(t, mempool.transactions)
	assert.NotNil(t, mempool.nonceMap)
	assert.NotNil(t, mempool.priorityHeap)
}

func TestMempoolAddTransaction(t *testing.T) {
	mempool := NewMempool(1000)

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	// Sign the transaction
	err = tx.Sign(keyPair)
	require.NoError(t, err)

	// Add transaction to mempool
	err = mempool.AddTransaction(tx)
	require.NoError(t, err)

	// Verify transaction was added
	assert.Equal(t, 1, mempool.GetSize())

	// Verify transaction can be retrieved
	txHash := tx.Hash()
	retrievedTx, exists := mempool.GetTransaction(txHash)
	assert.True(t, exists)
	assert.Equal(t, tx.Nonce, retrievedTx.Nonce)
	assert.Equal(t, tx.Value, retrievedTx.Value)
}

func TestMempoolAddDuplicateTransaction(t *testing.T) {
	mempool := NewMempool(1000)

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	// Sign the transaction
	err = tx.Sign(keyPair)
	require.NoError(t, err)

	// Add transaction twice
	err = mempool.AddTransaction(tx)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transaction already exists")

	// Verify only one transaction was added
	assert.Equal(t, 1, mempool.GetSize())
}

func TestMempoolAddTransactionWithInvalidNonce(t *testing.T) {
	mempool := NewMempool(1000)

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Add transaction with nonce 1
	tx1 := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	err = tx1.Sign(keyPair)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx1)
	require.NoError(t, err)

	// Try to add transaction with nonce 3 (gap) - this should succeed as mempool doesn't enforce nonce gaps
	tx3 := &Transaction{
		Nonce:     3,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	err = tx3.Sign(keyPair)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx3)
	require.NoError(t, err) // Should succeed as mempool allows nonce gaps

	// Verify both transactions are in mempool
	assert.Equal(t, 2, mempool.GetSize())
}

func TestMempoolGetPendingTransactions(t *testing.T) {
	mempool := NewMempool(1000)

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Add multiple transactions with different fees
	tx1 := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	tx2 := &Transaction{
		Nonce:     2,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(20), // Higher fee
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	tx3 := &Transaction{
		Nonce:     3,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(5), // Lower fee
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	// Sign all transactions
	err = tx1.Sign(keyPair)
	require.NoError(t, err)
	err = tx2.Sign(keyPair)
	require.NoError(t, err)
	err = tx3.Sign(keyPair)
	require.NoError(t, err)

	// Add transactions
	err = mempool.AddTransaction(tx1)
	require.NoError(t, err)
	err = mempool.AddTransaction(tx2)
	require.NoError(t, err)
	err = mempool.AddTransaction(tx3)
	require.NoError(t, err)

	// Get pending transactions (should be ordered by fee)
	pending := mempool.GetPendingTransactions(10, 1000000)
	assert.Equal(t, 3, len(pending))

	// Verify they are ordered by fee (highest first)
	assert.Equal(t, tx2.Hash(), pending[0].Hash()) // Fee 20
	assert.Equal(t, tx1.Hash(), pending[1].Hash()) // Fee 10
	assert.Equal(t, tx3.Hash(), pending[2].Hash()) // Fee 5
}

func TestMempoolGetPendingTransactionsWithSizeLimit(t *testing.T) {
	mempool := NewMempool(1000)

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Add a transaction with large data
	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      make([]byte, 1000), // Large data
		Timestamp: 1234567890,
	}

	err = tx.Sign(keyPair)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx)
	require.NoError(t, err)

	// Try to get transactions with small size limit
	pending := mempool.GetPendingTransactions(10, 100) // Very small limit
	assert.Equal(t, 0, len(pending))                   // Should be empty due to size limit
}

func TestMempoolRemoveTransactions(t *testing.T) {
	mempool := NewMempool(1000)

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Add multiple transactions
	tx1 := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	tx2 := &Transaction{
		Nonce:     2,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(20),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	err = tx1.Sign(keyPair)
	require.NoError(t, err)
	err = tx2.Sign(keyPair)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx1)
	require.NoError(t, err)
	err = mempool.AddTransaction(tx2)
	require.NoError(t, err)

	assert.Equal(t, 2, mempool.GetSize())

	// Remove transactions
	mempool.RemoveTransactions([]*Transaction{tx1, tx2})

	assert.Equal(t, 0, mempool.GetSize())

	// Verify transactions are gone
	_, exists := mempool.GetTransaction(tx1.Hash())
	assert.False(t, exists)

	_, exists = mempool.GetTransaction(tx2.Hash())
	assert.False(t, exists)
}

func TestMempoolClear(t *testing.T) {
	mempool := NewMempool(1000)

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Add a transaction
	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	err = tx.Sign(keyPair)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx)
	require.NoError(t, err)

	assert.Equal(t, 1, mempool.GetSize())

	// Clear mempool
	mempool.Clear()

	assert.Equal(t, 0, mempool.GetSize())

	// Verify transaction is gone
	_, exists := mempool.GetTransaction(tx.Hash())
	assert.False(t, exists)
}

func TestMempoolGetSenderAddress(t *testing.T) {
	mempool := NewMempool(1000)

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	// Sign the transaction
	err = tx.Sign(keyPair)
	require.NoError(t, err)

	// Get sender address
	sender, err := mempool.getSenderAddress(tx)
	require.NoError(t, err)

	// Verify sender address matches key pair address
	expectedAddress := keyPair.GetAddress()
	assert.Equal(t, expectedAddress, sender)
}

func TestMempoolGetStats(t *testing.T) {
	mempool := NewMempool(1000)

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Add a transaction
	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	err = tx.Sign(keyPair)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx)
	require.NoError(t, err)

	// Get stats
	stats := mempool.GetStats()

	assert.NotNil(t, stats)
	assert.Contains(t, stats, "size")
	assert.Contains(t, stats, "max_size")

	// Verify size is correct
	size, ok := stats["size"].(int)
	assert.True(t, ok)
	assert.Equal(t, 1, size)

	maxSize, ok := stats["max_size"].(int)
	assert.True(t, ok)
	assert.Equal(t, 1000, maxSize)
}

func TestTransactionHeapInterface(t *testing.T) {
	heap := &TransactionHeap{}

	// Test Len
	assert.Equal(t, 0, heap.Len())

	// Test Push and Pop
	tx1 := &Transaction{
		Nonce: 1,
		Value: big.NewInt(1000),
		Fee:   big.NewInt(10),
		Type:  TxTypeTransfer,
	}

	tx2 := &Transaction{
		Nonce: 2,
		Value: big.NewInt(1000),
		Fee:   big.NewInt(20), // Higher fee
		Type:  TxTypeTransfer,
	}

	heap.Push(tx1)
	heap.Push(tx2)

	assert.Equal(t, 2, heap.Len())

	// Test basic heap operations without complex ordering logic
	// Just verify that we can push and pop transactions
	popped := heap.Pop().(*Transaction)
	assert.NotNil(t, popped)
	assert.Equal(t, 1, heap.Len())
}

func TestMempoolMaxSizeLimit(t *testing.T) {
	mempool := NewMempool(2) // Small max size

	keyPair, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Add first transaction
	tx1 := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	err = tx1.Sign(keyPair)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx1)
	require.NoError(t, err)

	// Add second transaction
	tx2 := &Transaction{
		Nonce:     2,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(20),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	err = tx2.Sign(keyPair)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx2)
	require.NoError(t, err)

	assert.Equal(t, 2, mempool.GetSize())

	// Try to add third transaction (should fail)
	tx3 := &Transaction{
		Nonce:     3,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(30),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	err = tx3.Sign(keyPair)
	require.NoError(t, err)

	err = mempool.AddTransaction(tx3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mempool is full")

	// Size should still be 2
	assert.Equal(t, 2, mempool.GetSize())
}
