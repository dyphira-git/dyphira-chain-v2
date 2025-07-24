package types

import (
	"math/big"
	"testing"
	"time"

	"dyphira-node/crypto"

	"github.com/stretchr/testify/assert"
)

func TestValidateTransaction(t *testing.T) {
	// Valid transaction
	validTx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{1, 2, 3, 4, 5},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: time.Now().Unix(),
	}

	err := ValidateTransaction(validTx)
	assert.NoError(t, err)

	// Nil transaction
	err = ValidateTransaction(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transaction cannot be nil")

	// Invalid value (negative)
	invalidTx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{1, 2, 3, 4, 5},
		Value:     big.NewInt(-1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: time.Now().Unix(),
	}

	err = ValidateTransaction(invalidTx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid value")

	// Invalid fee (negative)
	invalidTx.Value = big.NewInt(1000)
	invalidTx.Fee = big.NewInt(-10)

	err = ValidateTransaction(invalidTx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid fee")

	// Invalid timestamp (too far in past)
	invalidTx.Fee = big.NewInt(10)
	invalidTx.Timestamp = time.Now().Unix() - 31536000*2 // 2 years ago

	err = ValidateTransaction(invalidTx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid timestamp")

	// Invalid data size
	invalidTx.Timestamp = time.Now().Unix()
	invalidTx.Data = make([]byte, 70000) // Too large

	err = ValidateTransaction(invalidTx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data too large")

	// Invalid transaction type
	invalidTx.Data = []byte{}
	invalidTx.Type = TxType(99) // Invalid type

	err = ValidateTransaction(invalidTx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown transaction type")
}

func TestValidateBlock(t *testing.T) {
	// Valid block
	validBlock := &Block{
		Header: BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{1, 2, 3, 4, 5},
		},
		Transactions: []Transaction{},
		ValidatorSig: []byte{1, 2, 3},
		Approvals:    [][]byte{},
	}

	err := ValidateBlock(validBlock)
	assert.NoError(t, err)

	// Nil block
	err = ValidateBlock(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "block cannot be nil")

	// Missing validator signature
	invalidBlock := &Block{
		Header: BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{1, 2, 3, 4, 5},
		},
		Transactions: []Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	err = ValidateBlock(invalidBlock)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing validator signature")

	// Too many approvals
	invalidBlock.ValidatorSig = []byte{1, 2, 3}
	invalidBlock.Approvals = make([][]byte, 22) // Too many

	err = ValidateBlock(invalidBlock)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many approvals")

	// Empty approval
	invalidBlock.Approvals = [][]byte{[]byte{}}

	err = ValidateBlock(invalidBlock)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty approval")
}

func TestValidateBlockHeader(t *testing.T) {
	// Valid header
	validHeader := &BlockHeader{
		Height:    1,
		Timestamp: time.Now().Unix(),
		Proposer:  crypto.Address{1, 2, 3, 4, 5},
	}

	err := ValidateBlockHeader(validHeader)
	assert.NoError(t, err)

	// Nil header
	err = ValidateBlockHeader(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "block header cannot be nil")

	// Invalid proposer address
	invalidHeader := &BlockHeader{
		Height:    1,
		Timestamp: time.Now().Unix(),
		Proposer:  crypto.Address{}, // Zero address
	}

	err = ValidateBlockHeader(invalidHeader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid proposer address")
}

func TestValidateValidator(t *testing.T) {
	// Valid validator
	validValidator := &Validator{
		Address:        crypto.Address{1, 2, 3, 4, 5},
		SelfStake:      big.NewInt(10000),
		DelegatedStake: big.NewInt(5000),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       time.Now().Unix(),
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(100),
		BlocksProposed: 10,
		BlocksApproved: 8,
	}

	err := ValidateValidator(validValidator)
	assert.NoError(t, err)

	// Nil validator
	err = ValidateValidator(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validator cannot be nil")

	// Invalid address
	invalidValidator := &Validator{
		Address:        crypto.Address{}, // Zero address
		SelfStake:      big.NewInt(10000),
		DelegatedStake: big.NewInt(5000),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       time.Now().Unix(),
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(100),
		BlocksProposed: 10,
		BlocksApproved: 8,
	}

	err = ValidateValidator(invalidValidator)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid validator address")

	// Invalid self stake (zero)
	invalidValidator.Address = crypto.Address{1, 2, 3, 4, 5}
	invalidValidator.SelfStake = big.NewInt(0)

	err = ValidateValidator(invalidValidator)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid self stake")

	// Invalid delegated stake (negative)
	invalidValidator.SelfStake = big.NewInt(10000)
	invalidValidator.DelegatedStake = big.NewInt(-1000)

	err = ValidateValidator(invalidValidator)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid delegated stake")
}

func TestValidateAccount(t *testing.T) {
	// Valid account
	validAccount := &Account{
		Balance: big.NewInt(1000),
		Nonce:   5,
	}

	err := ValidateAccount(validAccount)
	assert.NoError(t, err)

	// Nil account
	err = ValidateAccount(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account cannot be nil")

	// Invalid balance (negative)
	invalidAccount := &Account{
		Balance: big.NewInt(-1000),
		Nonce:   5,
	}

	err = ValidateAccount(invalidAccount)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid balance")
}

func TestValidateDelegation(t *testing.T) {
	// Valid delegation
	validDelegation := &Delegation{
		Delegator:   crypto.Address{1, 2, 3, 4, 5},
		Validator:   crypto.Address{6, 7, 8, 9, 10},
		Amount:      big.NewInt(1000),
		Rewards:     big.NewInt(50),
		LastClaimed: time.Now().Unix(),
	}

	err := ValidateDelegation(validDelegation)
	assert.NoError(t, err)

	// Nil delegation
	err = ValidateDelegation(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delegation cannot be nil")

	// Invalid delegator address
	invalidDelegation := &Delegation{
		Delegator:   crypto.Address{}, // Zero address
		Validator:   crypto.Address{6, 7, 8, 9, 10},
		Amount:      big.NewInt(1000),
		Rewards:     big.NewInt(50),
		LastClaimed: time.Now().Unix(),
	}

	err = ValidateDelegation(invalidDelegation)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid delegator address")

	// Invalid amount (zero)
	invalidDelegation.Delegator = crypto.Address{1, 2, 3, 4, 5}
	invalidDelegation.Amount = big.NewInt(0)

	err = ValidateDelegation(invalidDelegation)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid delegation amount")
}

func TestValidateConsensusMsg(t *testing.T) {
	// Valid message
	validMsg := &ConsensusMsg{
		Height:    100,
		BlockHash: crypto.Hash{},
		Signature: []byte{1, 2, 3},
		Sender:    crypto.Address{1, 2, 3, 4, 5},
		Type:      MsgTypeProposal,
	}

	err := ValidateConsensusMsg(validMsg)
	assert.NoError(t, err)

	// Nil message
	err = ValidateConsensusMsg(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "consensus message cannot be nil")

	// Missing signature
	invalidMsg := &ConsensusMsg{
		Height:    100,
		BlockHash: crypto.Hash{},
		Signature: []byte{},
		Sender:    crypto.Address{1, 2, 3, 4, 5},
		Type:      MsgTypeProposal,
	}

	err = ValidateConsensusMsg(invalidMsg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing signature")

	// Invalid sender address
	invalidMsg.Signature = []byte{1, 2, 3}
	invalidMsg.Sender = crypto.Address{} // Zero address

	err = ValidateConsensusMsg(invalidMsg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid sender address")
}

func TestValidateAddress(t *testing.T) {
	// Valid address
	validAddr := crypto.Address{1, 2, 3, 4, 5}
	err := ValidateAddress(validAddr)
	assert.NoError(t, err)

	// Invalid address (zero)
	invalidAddr := crypto.Address{}
	err = ValidateAddress(invalidAddr)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidAddress, err)
}

func TestValidateAmount(t *testing.T) {
	// Valid amount
	validAmount := big.NewInt(1000)
	err := ValidateAmount(validAmount)
	assert.NoError(t, err)

	// Zero amount
	zeroAmount := big.NewInt(0)
	err = ValidateAmount(zeroAmount)
	assert.NoError(t, err)

	// Invalid amount (negative)
	invalidAmount := big.NewInt(-1000)
	err = ValidateAmount(invalidAmount)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidAmount, err)

	// Nil amount
	err = ValidateAmount(nil)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidAmount, err)
}

func TestValidateStake(t *testing.T) {
	// Valid stake
	validStake := big.NewInt(1000)
	err := ValidateStake(validStake)
	assert.NoError(t, err)

	// Invalid stake (zero)
	zeroStake := big.NewInt(0)
	err = ValidateStake(zeroStake)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidStake, err)

	// Invalid stake (negative)
	invalidStake := big.NewInt(-1000)
	err = ValidateStake(invalidStake)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidStake, err)

	// Nil stake
	err = ValidateStake(nil)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidStake, err)
}

func TestValidateNonce(t *testing.T) {
	// Any nonce should be valid
	err := ValidateNonce(0)
	assert.NoError(t, err)

	err = ValidateNonce(1000)
	assert.NoError(t, err)

	err = ValidateNonce(^uint64(0)) // Max uint64
	assert.NoError(t, err)
}

func TestValidateFee(t *testing.T) {
	// Valid fee
	validFee := big.NewInt(10)
	err := ValidateFee(validFee)
	assert.NoError(t, err)

	// Zero fee
	zeroFee := big.NewInt(0)
	err = ValidateFee(zeroFee)
	assert.NoError(t, err)

	// Invalid fee (negative)
	invalidFee := big.NewInt(-10)
	err = ValidateFee(invalidFee)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidFee, err)

	// Nil fee
	err = ValidateFee(nil)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidFee, err)
}

func TestValidateTimestamp(t *testing.T) {
	// Valid timestamp (now)
	now := time.Now().Unix()
	err := ValidateTimestamp(now)
	assert.NoError(t, err)

	// Valid timestamp (1 year ago)
	oneYearAgo := now - 31536000
	err = ValidateTimestamp(oneYearAgo)
	assert.NoError(t, err)

	// Valid timestamp (1 year in future)
	oneYearFuture := now + 31536000
	err = ValidateTimestamp(oneYearFuture)
	assert.NoError(t, err)

	// Invalid timestamp (too far in past)
	tooFarPast := now - 31536000*2
	err = ValidateTimestamp(tooFarPast)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidTimestamp, err)

	// Invalid timestamp (too far in future)
	tooFarFuture := now + 31536000*2
	err = ValidateTimestamp(tooFarFuture)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidTimestamp, err)
}

func TestValidateBlockHeight(t *testing.T) {
	// Any height should be valid
	err := ValidateBlockHeight(0)
	assert.NoError(t, err)

	err = ValidateBlockHeight(1000)
	assert.NoError(t, err)

	err = ValidateBlockHeight(^uint64(0)) // Max uint64
	assert.NoError(t, err)
}

func TestValidateReputation(t *testing.T) {
	// Any reputation should be valid
	err := ValidateReputation(0)
	assert.NoError(t, err)

	err = ValidateReputation(1000)
	assert.NoError(t, err)

	err = ValidateReputation(^uint64(0)) // Max uint64
	assert.NoError(t, err)
}

func TestValidateTxType(t *testing.T) {
	// Valid transaction types
	validTypes := []TxType{
		TxTypeTransfer,
		TxTypeStake,
		TxTypeUnstake,
		TxTypeDelegate,
		TxTypeUndelegate,
		TxTypeClaimRewards,
	}

	for _, txType := range validTypes {
		err := ValidateTxType(txType)
		assert.NoError(t, err)
	}

	// Invalid transaction type
	err := ValidateTxType(TxType(99))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown transaction type")
}

func TestValidateMsgType(t *testing.T) {
	// Valid message types
	validTypes := []MsgType{
		MsgTypeProposal,
		MsgTypeApproval,
		MsgTypeTimeout,
	}

	for _, msgType := range validTypes {
		err := ValidateMsgType(msgType)
		assert.NoError(t, err)
	}

	// Invalid message type
	err := ValidateMsgType(MsgType(99))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown message type")
}

func TestValidateSignature(t *testing.T) {
	// Valid signature
	validSig := &Signature{
		V: 27,
		R: [32]byte{1, 2, 3},
		S: [32]byte{4, 5, 6},
	}

	err := ValidateSignature(validSig)
	assert.NoError(t, err)

	// Nil signature
	err = ValidateSignature(nil)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidSignature, err)

	// Invalid V value
	invalidSig := &Signature{
		V: 26, // Invalid V
		R: [32]byte{1, 2, 3},
		S: [32]byte{4, 5, 6},
	}

	err = ValidateSignature(invalidSig)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidSignature, err)

	// Zero R value
	invalidSig.V = 27
	invalidSig.R = [32]byte{}

	err = ValidateSignature(invalidSig)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidSignature, err)

	// Zero S value
	invalidSig.R = [32]byte{1, 2, 3}
	invalidSig.S = [32]byte{}

	err = ValidateSignature(invalidSig)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidSignature, err)
}

func TestValidateData(t *testing.T) {
	// Valid data
	validData := []byte{1, 2, 3, 4, 5}
	err := ValidateData(validData)
	assert.NoError(t, err)

	// Nil data (valid)
	err = ValidateData(nil)
	assert.NoError(t, err)

	// Empty data (valid)
	emptyData := []byte{}
	err = ValidateData(emptyData)
	assert.NoError(t, err)

	// Data at size limit (valid)
	limitData := make([]byte, 65535)
	err = ValidateData(limitData)
	assert.NoError(t, err)

	// Data too large
	largeData := make([]byte, 65536)
	err = ValidateData(largeData)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidData, err)
}
