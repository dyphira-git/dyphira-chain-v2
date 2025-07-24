package state

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"dyphira-node/crypto"
	"dyphira-node/types"

	"github.com/stretchr/testify/assert"
)

func TestNewStorage(t *testing.T) {
	// Test creating new storage
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	assert.NotNil(t, storage)
	assert.NotNil(t, storage.db)

	// Clean up
	err = storage.Close()
	assert.NoError(t, err)
}

func TestStoreAndGetBlock(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Create a test block
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	// Store block
	err = storage.StoreBlock(block)
	assert.NoError(t, err)

	// Get block by height
	retrievedBlock, err := storage.GetBlockByHeight(1)
	assert.NoError(t, err)
	assert.Equal(t, block.Header.Height, retrievedBlock.Header.Height)

	// Get block by hash
	retrievedBlockByHash, err := storage.GetBlockByHash(block.Hash())
	assert.NoError(t, err)
	assert.Equal(t, block.Header.Height, retrievedBlockByHash.Header.Height)
}

func TestStoreAndGetTransaction(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Create a test transaction
	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	tx := &types.Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Timestamp: time.Now().Unix(),
		Type:      types.TxTypeTransfer,
		Data:      []byte{},
	}

	// Sign the transaction
	err = tx.Sign(keyPair)
	assert.NoError(t, err)

	// Store transaction (via block)
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{*tx},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	err = storage.StoreBlock(block)
	assert.NoError(t, err)

	// Get transaction
	retrievedTx, err := storage.GetTransaction(tx.Hash())
	assert.NoError(t, err)
	assert.Equal(t, tx.Nonce, retrievedTx.Nonce)
}

func TestSetAndGetLatestBlock(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Set latest block
	err = storage.SetLatestBlock(100)
	assert.NoError(t, err)

	// Get latest block
	height, err := storage.GetLatestBlock()
	assert.NoError(t, err)
	assert.Equal(t, uint64(100), height)
}

func TestStoreAndGetGenesisBlock(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Create genesis block
	genesis := &types.Block{
		Header: types.BlockHeader{
			Height:    0,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	// Store genesis block
	err = storage.StoreGenesis(genesis)
	assert.NoError(t, err)

	// Get genesis block
	retrievedGenesis, err := storage.GetGenesis()
	assert.NoError(t, err)
	assert.Equal(t, genesis.Header.Height, retrievedGenesis.Header.Height)
}

func TestDeleteBlock(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Create and store a block
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	err = storage.StoreBlock(block)
	assert.NoError(t, err)

	// Verify block exists
	retrievedBlock, err := storage.GetBlockByHeight(1)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedBlock)

	// Delete block
	err = storage.DeleteBlock(1)
	assert.NoError(t, err)

	// Verify block is deleted
	_, err = storage.GetBlockByHeight(1)
	assert.Error(t, err)
}

func TestGetNonExistentBlock(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Try to get non-existent block
	_, err = storage.GetBlockByHeight(999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "block not found")
}

func TestGetNonExistentTransaction(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Try to get non-existent transaction
	_, err = storage.GetTransaction(crypto.Hash{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transaction not found")
}

func TestGetNonExistentGenesisBlock(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Try to get non-existent genesis block
	genesis, err := storage.GetGenesis()
	if err != nil {
		// Expected error for non-existent genesis block
		assert.Contains(t, err.Error(), "genesis block not found")
		assert.Nil(t, genesis)
	} else {
		// If no error, genesis block should exist
		assert.NotNil(t, genesis)
	}
}

func TestLargeBlockStorage(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Create a block with many transactions
	transactions := make([]types.Transaction, 1000)
	for i := 0; i < 1000; i++ {
		transactions[i] = types.Transaction{
			Nonce:     uint64(i),
			To:        crypto.Address{},
			Value:     big.NewInt(int64(i * 100)),
			Fee:       big.NewInt(10),
			Timestamp: time.Now().Unix(),
			Type:      types.TxTypeTransfer,
			Data:      []byte{},
		}
	}

	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: transactions,
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	// Store large block
	err = storage.StoreBlock(block)
	assert.NoError(t, err)

	// Retrieve large block
	retrievedBlock, err := storage.GetBlockByHeight(1)
	assert.NoError(t, err)
	assert.Equal(t, len(transactions), len(retrievedBlock.Transactions))
}

func TestConcurrentBlockStorage(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)
	defer storage.Close()

	// Test concurrent block storage
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(index int) {
			block := &types.Block{
				Header: types.BlockHeader{
					Height:    uint64(index + 100),
					Timestamp: time.Now().Unix(),
					Proposer:  crypto.Address{},
				},
				Transactions: []types.Transaction{},
				ValidatorSig: []byte{},
				Approvals:    [][]byte{},
			}

			err := storage.StoreBlock(block)
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all blocks were stored
	for i := 0; i < 10; i++ {
		block, err := storage.GetBlockByHeight(uint64(i + 100))
		assert.NoError(t, err)
		assert.Equal(t, uint64(i+100), block.Header.Height)
	}
}

func TestStorageClose(t *testing.T) {
	storage, err := NewStorage("./test-storage.db")
	assert.NoError(t, err)

	// Close storage
	err = storage.Close()
	assert.NoError(t, err)

	// Try to use closed storage (should fail)
	err = storage.SetLatestBlock(1)
	assert.Error(t, err)
}

func TestTransactionJSONMarshaling(t *testing.T) {
	// Create a test transaction
	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	tx := &types.Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Timestamp: time.Now().Unix(),
		Type:      types.TxTypeTransfer,
		Data:      []byte{},
	}

	// Sign the transaction
	err = tx.Sign(keyPair)
	assert.NoError(t, err)

	// Marshal to JSON
	txData, err := json.Marshal(tx)
	assert.NoError(t, err)
	t.Logf("Marshaled JSON: %s", string(txData))

	// Unmarshal from JSON
	var retrievedTx types.Transaction
	err = json.Unmarshal(txData, &retrievedTx)
	assert.NoError(t, err)

	// Verify the transaction
	assert.Equal(t, tx.Nonce, retrievedTx.Nonce)
	assert.Equal(t, tx.Value.String(), retrievedTx.Value.String())
	assert.Equal(t, tx.Fee.String(), retrievedTx.Fee.String())
}

func TestBlockJSONMarshaling(t *testing.T) {
	// Create a test transaction
	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	tx := &types.Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Timestamp: time.Now().Unix(),
		Type:      types.TxTypeTransfer,
		Data:      []byte{},
	}

	// Sign the transaction
	err = tx.Sign(keyPair)
	assert.NoError(t, err)

	// Create a block with the transaction
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{*tx},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	// Marshal block to JSON
	blockData, err := json.Marshal(block)
	assert.NoError(t, err)
	t.Logf("Marshaled block JSON: %s", string(blockData))

	// Unmarshal block from JSON
	var retrievedBlock types.Block
	err = json.Unmarshal(blockData, &retrievedBlock)
	assert.NoError(t, err)

	// Verify the block
	assert.Equal(t, block.Header.Height, retrievedBlock.Header.Height)
	assert.Len(t, retrievedBlock.Transactions, 1)
	assert.Equal(t, tx.Value.String(), retrievedBlock.Transactions[0].Value.String())
	assert.Equal(t, tx.Fee.String(), retrievedBlock.Transactions[0].Fee.String())
}
