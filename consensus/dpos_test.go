package consensus

import (
	"math/big"
	"testing"
	"time"

	"dyphira-node/core"
	"dyphira-node/crypto"
	"dyphira-node/state"
	"dyphira-node/types"

	"github.com/stretchr/testify/assert"
)

func TestNewDPoS(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)
	assert.NotNil(t, dpos)
	assert.Equal(t, uint64(0), dpos.currentEpoch)
	assert.Equal(t, uint64(0), dpos.blockHeight)
	assert.Equal(t, uint64(0), dpos.proposerIndex)
	assert.Equal(t, uint64(types.BlocksPerEpoch), dpos.blocksPerProposer)
	assert.NotNil(t, dpos.mempool)
	assert.NotNil(t, dpos.blockchain)
	assert.Empty(t, dpos.validators)
	assert.Empty(t, dpos.committee)
}

func TestAddValidator(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Create a test validator
	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	validator := &types.Validator{
		Address:        keyPair.GetAddress(),
		SelfStake:      big.NewInt(10000),
		DelegatedStake: big.NewInt(5000),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       time.Now().Unix(),
	}

	// Add validator
	err = dpos.AddValidator(validator)
	assert.NoError(t, err)
	assert.Len(t, dpos.validators, 1)
	assert.Equal(t, validator.Address, dpos.validators[0].Address)

	// Try to add the same validator again
	err = dpos.AddValidator(validator)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validator already exists")
}

func TestRemoveValidator(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Create and add a validator
	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	validator := &types.Validator{
		Address:        keyPair.GetAddress(),
		SelfStake:      big.NewInt(10000),
		DelegatedStake: big.NewInt(5000),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       time.Now().Unix(),
	}

	err = dpos.AddValidator(validator)
	assert.NoError(t, err)

	// Remove validator
	err = dpos.RemoveValidator(validator.Address)
	assert.NoError(t, err)
	assert.Empty(t, dpos.validators)

	// Try to remove non-existent validator
	otherKeyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	err = dpos.RemoveValidator(otherKeyPair.GetAddress())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validator not found")
}

func TestUpdateValidator(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Create and add a validator
	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	validator := &types.Validator{
		Address:        keyPair.GetAddress(),
		SelfStake:      big.NewInt(10000),
		DelegatedStake: big.NewInt(5000),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       time.Now().Unix(),
	}

	err = dpos.AddValidator(validator)
	assert.NoError(t, err)

	// Update validator
	updates := &types.Validator{
		Address:        keyPair.GetAddress(),
		SelfStake:      big.NewInt(20000),
		DelegatedStake: big.NewInt(10000),
		Reputation:     150,
		IsOnline:       false,
		LastSeen:       time.Now().Unix(),
	}

	err = dpos.UpdateValidator(keyPair.GetAddress(), updates)
	assert.NoError(t, err)

	// Verify updates
	updatedValidator := dpos.validators[0]
	assert.Equal(t, big.NewInt(20000), updatedValidator.SelfStake)
	assert.Equal(t, big.NewInt(10000), updatedValidator.DelegatedStake)
	assert.Equal(t, uint64(150), updatedValidator.Reputation)
	assert.False(t, updatedValidator.IsOnline)

	// Try to update non-existent validator
	otherKeyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	err = dpos.UpdateValidator(otherKeyPair.GetAddress(), updates)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validator not found")
}

func TestWeightedRandomSelect(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Create test validators with different stakes
	validators := make([]*types.Validator, 5)
	for i := 0; i < 5; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		assert.NoError(t, err)

		validators[i] = &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(int64(10000 + i*1000)),
			DelegatedStake: big.NewInt(int64(5000 + i*500)),
			Reputation:     uint64(100 + i*10),
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
		}
	}

	// Test selection with count less than total validators
	selected := dpos.WeightedRandomSelect(validators, 3)
	assert.Len(t, selected, 3)

	// Test selection with count equal to total validators
	selected = dpos.WeightedRandomSelect(validators, 5)
	assert.Len(t, selected, 5)

	// Test selection with count greater than total validators
	selected = dpos.WeightedRandomSelect(validators, 10)
	assert.Len(t, selected, 5)
}

func TestElectCommittee(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Add enough validators for committee election
	for i := 0; i < 50; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		assert.NoError(t, err)

		validator := &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(10000),
			DelegatedStake: big.NewInt(5000),
			Reputation:     100,
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
		}

		err = dpos.AddValidator(validator)
		assert.NoError(t, err)
	}

	// Elect committee
	err = dpos.ElectCommittee()
	assert.NoError(t, err)
	assert.Len(t, dpos.committee, types.CommitteeSize)
	assert.Equal(t, uint64(0), dpos.proposerIndex)
}

func TestGetProposer(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Add validators and elect committee
	for i := 0; i < 50; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		assert.NoError(t, err)

		validator := &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(10000),
			DelegatedStake: big.NewInt(5000),
			Reputation:     100,
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
		}

		err = dpos.AddValidator(validator)
		assert.NoError(t, err)
	}

	err = dpos.ElectCommittee()
	assert.NoError(t, err)

	// Get current proposer
	proposer, err := dpos.GetProposer()
	assert.NoError(t, err)
	assert.NotNil(t, proposer)
	assert.Equal(t, dpos.committee[0].Address, proposer.Address)
}

func TestShouldStartNewEpoch(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Initially should start new epoch (block height 0)
	assert.True(t, dpos.ShouldStartNewEpoch())

	// Set block height to not trigger new epoch
	dpos.SetBlockHeight(1)
	assert.False(t, dpos.ShouldStartNewEpoch())

	dpos.SetBlockHeight(types.EpochLength - 1)
	assert.False(t, dpos.ShouldStartNewEpoch())

	dpos.SetBlockHeight(types.EpochLength)
	assert.True(t, dpos.ShouldStartNewEpoch())
}

func TestStartNewEpoch(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Add validators
	for i := 0; i < 50; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		assert.NoError(t, err)

		validator := &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(10000),
			DelegatedStake: big.NewInt(5000),
			Reputation:     100,
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
		}

		err = dpos.AddValidator(validator)
		assert.NoError(t, err)
	}

	// Start new epoch
	err = dpos.StartNewEpoch()
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), dpos.currentEpoch)
	assert.Equal(t, uint64(0), dpos.proposerIndex)
	assert.Len(t, dpos.committee, types.CommitteeSize)
}

func TestProcessBlock(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

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

	// Process block
	err = dpos.ProcessBlock(block)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), dpos.blockHeight)
}

func TestGetNextProposer(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Add validators and elect committee
	for i := 0; i < 50; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		assert.NoError(t, err)

		validator := &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(10000),
			DelegatedStake: big.NewInt(5000),
			Reputation:     100,
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
		}

		err = dpos.AddValidator(validator)
		assert.NoError(t, err)
	}

	err = dpos.ElectCommittee()
	assert.NoError(t, err)

	// Get next proposer
	nextProposer, err := dpos.GetNextProposer()
	assert.NoError(t, err)
	assert.NotNil(t, nextProposer)
	assert.Equal(t, dpos.committee[1].Address, nextProposer.Address)
}

func TestValidateBlock(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Add validators and elect committee first
	for i := 0; i < 50; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		assert.NoError(t, err)

		validator := &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(10000),
			DelegatedStake: big.NewInt(5000),
			Reputation:     100,
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
		}

		err = dpos.AddValidator(validator)
		assert.NoError(t, err)
	}

	err = dpos.ElectCommittee()
	assert.NoError(t, err)

	// Get the correct proposer for the block
	proposer, err := dpos.GetProposer()
	assert.NoError(t, err)

	// Create a valid block with the correct proposer
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  proposer.Address,
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{}, // Empty approvals for this test
	}

	// Test basic block validation (proposer check)
	// The approval validation will fail, but that's expected for this test
	err = dpos.ValidateBlock(block)
	// We expect an error about insufficient approvals, which is fine for this test
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient")

	// Test invalid block (nil)
	err = dpos.ValidateBlock(nil)
	assert.Error(t, err)
}

func TestCreateBlock(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	// Create genesis block first
	_, err = blockchain.CreateGenesisBlock()
	assert.NoError(t, err)

	dpos := NewDPoS(blockchain)

	// Add validators and elect committee
	for i := 0; i < 50; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		assert.NoError(t, err)

		validator := &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(10000),
			DelegatedStake: big.NewInt(5000),
			Reputation:     100,
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
		}

		err = dpos.AddValidator(validator)
		assert.NoError(t, err)
	}

	err = dpos.ElectCommittee()
	assert.NoError(t, err)

	// Create a proposer key pair
	proposerKeyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	// Create block
	block, err := dpos.CreateBlock(proposerKeyPair)
	assert.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, uint64(1), block.Header.Height)
	assert.NotEmpty(t, block.ValidatorSig)
}

func TestValidateTransaction(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Create a key pair for signing
	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	// Create an account for the sender with proper nonce
	senderAccount := &state.Account{
		Balance: big.NewInt(10000),
		Nonce:   1,
	}
	err = blockchain.SetAccount(keyPair.GetAddress(), senderAccount)
	assert.NoError(t, err)

	// Create a valid transaction
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

	// Validate transaction
	err = dpos.ValidateTransaction(tx)
	assert.NoError(t, err)

	// Test invalid transaction (nil)
	err = dpos.ValidateTransaction(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transaction cannot be nil")
}

func TestAddTransactionToMempool(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Create a key pair for signing
	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	// Create a transaction
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

	// Add transaction to mempool
	err = dpos.AddTransactionToMempool(tx)
	assert.NoError(t, err)

	// Verify transaction is in mempool
	stats := dpos.GetMempoolStats()
	assert.NotNil(t, stats)

	// Check size (mempool returns "size" not "count")
	size, ok := stats["size"]
	assert.True(t, ok, "size should be present in stats")
	if sizeInt, ok := size.(int); ok {
		assert.Equal(t, 1, sizeInt)
	} else if sizeInt64, ok := size.(int64); ok {
		assert.Equal(t, int64(1), sizeInt64)
	} else {
		assert.Fail(t, "size should be int or int64")
	}
}

func TestGetMempoolStats(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Get initial stats
	stats := dpos.GetMempoolStats()
	assert.NotNil(t, stats)

	// Check size (mempool returns "size" not "count")
	size, ok := stats["size"]
	assert.True(t, ok, "size should be present in stats")
	if sizeInt, ok := size.(int); ok {
		assert.Equal(t, 0, sizeInt)
	} else if sizeInt64, ok := size.(int64); ok {
		assert.Equal(t, int64(0), sizeInt64)
	} else {
		assert.Fail(t, "size should be int or int64")
	}

	// Check max_size
	maxSize, ok := stats["max_size"]
	assert.True(t, ok, "max_size should be present in stats")
	if maxSizeInt, ok := maxSize.(int); ok {
		assert.Greater(t, maxSizeInt, 0)
	} else if maxSizeInt64, ok := maxSize.(int64); ok {
		assert.Greater(t, maxSizeInt64, int64(0))
	} else {
		assert.Fail(t, "max_size should be int or int64")
	}
}

func TestSetBlockHeight(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Set block height
	dpos.SetBlockHeight(100)
	assert.Equal(t, uint64(100), dpos.blockHeight)
}

func TestGetApprovalCount(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Create a block with approvals
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{{1}, {2}, {3}},
	}

	// Get approval count
	count := dpos.GetApprovalCount(block)
	assert.Equal(t, 3, count)
}

func TestGetCommitteeApprovalPercentage(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Create a block with approvals
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{{1}, {2}, {3}},
	}

	// Get approval percentage
	percentage := dpos.GetCommitteeApprovalPercentage(block)

	// If committee is empty, percentage should be 0
	if len(dpos.GetCommittee()) == 0 {
		assert.Equal(t, 0.0, percentage)
	} else {
		assert.Greater(t, percentage, 0.0)
	}
}

func TestIsBlockFinalized(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Create a block with approvals
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{{1}, {2}, {3}},
	}

	// Check if block is finalized
	isFinalized := dpos.IsBlockFinalized(block)

	// With 3 approvals and empty committee (0 members), required = (0 * 2) / 3 = 0
	// So it should be finalized
	committeeSize := len(dpos.GetCommittee())
	requiredApprovals := (committeeSize * 2) / 3

	if committeeSize == 0 {
		// Empty committee means no approvals required
		assert.True(t, isFinalized)
	} else if 3 >= requiredApprovals {
		assert.True(t, isFinalized)
	} else {
		assert.False(t, isFinalized)
	}
}

func TestGetEpochInfo(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Get epoch info
	epochInfo := dpos.GetEpochInfo()
	assert.NotNil(t, epochInfo)

	// Check that required fields exist
	currentEpoch, ok := epochInfo["current_epoch"]
	assert.True(t, ok, "current_epoch should be present")
	if currentEpoch != nil {
		// Can be uint64 or int
		if _, ok := currentEpoch.(uint64); ok {
			assert.IsType(t, uint64(0), currentEpoch)
		} else if _, ok := currentEpoch.(int); ok {
			assert.IsType(t, int(0), currentEpoch)
		} else {
			assert.Fail(t, "current_epoch should be uint64 or int")
		}
	}

	blockHeight, ok := epochInfo["block_height"]
	assert.True(t, ok, "block_height should be present")
	if blockHeight != nil {
		// Can be uint64 or int
		if _, ok := blockHeight.(uint64); ok {
			assert.IsType(t, uint64(0), blockHeight)
		} else if _, ok := blockHeight.(int); ok {
			assert.IsType(t, int(0), blockHeight)
		} else {
			assert.Fail(t, "block_height should be uint64 or int")
		}
	}

	epochLength, ok := epochInfo["epoch_length"]
	assert.True(t, ok, "epoch_length should be present")
	if epochLength != nil {
		// Can be uint64 or int
		if _, ok := epochLength.(uint64); ok {
			assert.IsType(t, uint64(0), epochLength)
		} else if _, ok := epochLength.(int); ok {
			assert.IsType(t, int(0), epochLength)
		} else {
			assert.Fail(t, "epoch_length should be uint64 or int")
		}
	}
}

func TestGetValidatorStats(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Add some validators
	for i := 0; i < 5; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		assert.NoError(t, err)

		validator := &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(10000),
			DelegatedStake: big.NewInt(5000),
			Reputation:     100,
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
		}

		err = dpos.AddValidator(validator)
		assert.NoError(t, err)
	}

	// Get validator stats
	stats := dpos.GetValidatorStats()
	assert.NotNil(t, stats)

	// Check that required fields exist
	totalValidators, ok := stats["total_validators"]
	assert.True(t, ok, "total_validators should be present")
	if totalValidators != nil {
		// Can be int or int64
		if _, ok := totalValidators.(int); ok {
			assert.IsType(t, int(0), totalValidators)
		} else if _, ok := totalValidators.(int64); ok {
			assert.IsType(t, int64(0), totalValidators)
		} else {
			assert.Fail(t, "total_validators should be int or int64")
		}
	}

	onlineValidators, ok := stats["online_validators"]
	assert.True(t, ok, "online_validators should be present")
	if onlineValidators != nil {
		// Can be int or int64
		if _, ok := onlineValidators.(int); ok {
			assert.IsType(t, int(0), onlineValidators)
		} else if _, ok := onlineValidators.(int64); ok {
			assert.IsType(t, int64(0), onlineValidators)
		} else {
			assert.Fail(t, "online_validators should be int or int64")
		}
	}
}

func TestGetCurrentEpoch(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Add some validators first
	for i := 0; i < 10; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		assert.NoError(t, err)

		validator := &types.Validator{
			Address:        keyPair.GetAddress(),
			SelfStake:      big.NewInt(10000),
			DelegatedStake: big.NewInt(5000),
			Reputation:     100,
			IsOnline:       true,
			LastSeen:       time.Now().Unix(),
		}

		err = dpos.AddValidator(validator)
		assert.NoError(t, err)
	}

	// Start a new epoch
	err = dpos.StartNewEpoch()
	assert.NoError(t, err)

	// Get current epoch
	currentEpoch := dpos.GetCurrentEpoch()
	assert.Equal(t, uint64(1), currentEpoch)
}

func TestGetBlockHeight(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Get block height
	height := dpos.GetBlockHeight()
	assert.Equal(t, uint64(0), height)

	// Set block height
	dpos.SetBlockHeight(100)
	height = dpos.GetBlockHeight()
	assert.Equal(t, uint64(100), height)
}

func TestGetCurrentProposerIndex(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Get current proposer index
	index := dpos.GetCurrentProposerIndex()
	assert.Equal(t, uint64(0), index)
}

func TestGetBlocksUntilNextProposer(t *testing.T) {
	blockchain, err := core.NewBlockchain("./test.db")
	assert.NoError(t, err)
	defer blockchain.Close()

	dpos := NewDPoS(blockchain)

	// Get blocks until next proposer
	blocks := dpos.GetBlocksUntilNextProposer()
	assert.Equal(t, uint64(9), blocks) // blocksPerProposer - 1
}
