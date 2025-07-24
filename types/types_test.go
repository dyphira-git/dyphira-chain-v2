package types

import (
	"math/big"
	"testing"

	"dyphira-node/crypto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockHash(t *testing.T) {
	block := &Block{
		Header: BlockHeader{
			PrevHash:           crypto.Hash{},
			Height:             1,
			Timestamp:          1234567890,
			Proposer:           crypto.Address{},
			TxRoot:             crypto.Hash{},
			AccountStateRoot:   crypto.Hash{},
			ValidatorStateRoot: crypto.Hash{},
			TxStateRoot:        crypto.Hash{},
		},
		Transactions: []Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	hash := block.Hash()
	assert.NotEqual(t, crypto.Hash{}, hash)
	assert.Equal(t, 32, len(hash))
}

func TestBlockHeaderBytes(t *testing.T) {
	header := BlockHeader{
		PrevHash:           crypto.Hash{},
		Height:             1,
		Timestamp:          1234567890,
		Proposer:           crypto.Address{},
		TxRoot:             crypto.Hash{},
		AccountStateRoot:   crypto.Hash{},
		ValidatorStateRoot: crypto.Hash{},
		TxStateRoot:        crypto.Hash{},
	}

	bytes := header.Bytes()
	assert.NotNil(t, bytes)
	assert.True(t, len(bytes) > 0)
}

func TestTransactionHash(t *testing.T) {
	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	hash := tx.Hash()
	assert.NotEqual(t, crypto.Hash{}, hash)
	assert.Equal(t, 32, len(hash))
}

func TestTransactionBytes(t *testing.T) {
	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	bytes, err := tx.Bytes()
	require.NoError(t, err)
	assert.NotNil(t, bytes)
	assert.True(t, len(bytes) > 0)
}

func TestTransactionBytesWithLargeValue(t *testing.T) {
	// Create a very large value that would exceed 255 bytes when serialized
	largeValue := new(big.Int).Exp(big.NewInt(2), big.NewInt(2048), nil)

	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     largeValue,
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	_, err := tx.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "value too large")
}

func TestTransactionBytesWithLargeFee(t *testing.T) {
	// Create a very large fee that would exceed 255 bytes when serialized
	largeFee := new(big.Int).Exp(big.NewInt(2), big.NewInt(2048), nil)

	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       largeFee,
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	_, err := tx.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fee too large")
}

func TestTransactionBytesWithLargeData(t *testing.T) {
	// Create data that exceeds 65535 bytes
	largeData := make([]byte, 70000)

	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      largeData,
		Timestamp: 1234567890,
	}

	_, err := tx.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data too large")
}

func TestTransactionSignAndVerify(t *testing.T) {
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

	// Verify the signature
	isValid := tx.Verify()
	assert.True(t, isValid)
}

func TestTransactionVerifyInvalid(t *testing.T) {
	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
		Signature: Signature{
			V: 27,
			R: [32]byte{},
			S: [32]byte{},
		},
	}

	// Verify should fail with invalid signature
	isValid := tx.Verify()
	assert.False(t, isValid)
}

func TestValidatorGetTotalStake(t *testing.T) {
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

	totalStake := validator.GetTotalStake()
	expected := big.NewInt(1500) // 1000 + 500
	assert.Equal(t, expected, totalStake)
}

func TestValidatorIsEligible(t *testing.T) {
	validator := &Validator{
		Address:        crypto.Address{},
		SelfStake:      big.NewInt(10000), // Above minimum
		DelegatedStake: big.NewInt(5000),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       1234567890,
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(100),
		BlocksProposed: 10,
		BlocksApproved: 8,
	}

	isEligible := validator.IsEligible()
	assert.True(t, isEligible)
}

func TestValidatorIsEligibleInsufficientStake(t *testing.T) {
	validator := &Validator{
		Address:        crypto.Address{},
		SelfStake:      big.NewInt(5000), // Below minimum
		DelegatedStake: big.NewInt(1000),
		Reputation:     100,
		IsOnline:       true,
		LastSeen:       1234567890,
		Delegators:     make(map[crypto.Address]*big.Int),
		TotalRewards:   big.NewInt(100),
		BlocksProposed: 10,
		BlocksApproved: 8,
	}

	isEligible := validator.IsEligible()
	assert.False(t, isEligible)
}

func TestNewStakeTransaction(t *testing.T) {
	amount := big.NewInt(10000)
	fee := big.NewInt(10)

	tx := NewStakeTransaction(1, amount, fee)

	assert.Equal(t, uint64(1), tx.Nonce)
	assert.Equal(t, crypto.Address{}, tx.To) // Zero address for staking
	assert.Equal(t, amount, tx.Value)
	assert.Equal(t, fee, tx.Fee)
	assert.Equal(t, TxTypeStake, tx.Type)
	assert.Equal(t, []byte{}, tx.Data)
}

func TestNewUnstakeTransaction(t *testing.T) {
	amount := big.NewInt(5000)
	fee := big.NewInt(10)

	tx := NewUnstakeTransaction(1, amount, fee)

	assert.Equal(t, uint64(1), tx.Nonce)
	assert.Equal(t, crypto.Address{}, tx.To) // Zero address for unstaking
	assert.Equal(t, amount, tx.Value)
	assert.Equal(t, fee, tx.Fee)
	assert.Equal(t, TxTypeUnstake, tx.Type)
	assert.Equal(t, []byte{}, tx.Data)
}

func TestNewDelegateTransaction(t *testing.T) {
	validator := crypto.Address{1, 2, 3, 4, 5} // Test address
	amount := big.NewInt(1000)
	fee := big.NewInt(10)

	tx := NewDelegateTransaction(1, validator, amount, fee)

	assert.Equal(t, uint64(1), tx.Nonce)
	assert.Equal(t, validator, tx.To)
	assert.Equal(t, amount, tx.Value)
	assert.Equal(t, fee, tx.Fee)
	assert.Equal(t, TxTypeDelegate, tx.Type)
	assert.Equal(t, []byte{}, tx.Data)
}

func TestNewUndelegateTransaction(t *testing.T) {
	validator := crypto.Address{1, 2, 3, 4, 5} // Test address
	amount := big.NewInt(1000)
	fee := big.NewInt(10)

	tx := NewUndelegateTransaction(1, validator, amount, fee)

	assert.Equal(t, uint64(1), tx.Nonce)
	assert.Equal(t, validator, tx.To)
	assert.Equal(t, amount, tx.Value)
	assert.Equal(t, fee, tx.Fee)
	assert.Equal(t, TxTypeUndelegate, tx.Type)
	assert.Equal(t, []byte{}, tx.Data)
}

func TestNewClaimRewardsTransaction(t *testing.T) {
	validator := crypto.Address{1, 2, 3, 4, 5} // Test address
	fee := big.NewInt(10)

	tx := NewClaimRewardsTransaction(1, validator, fee)

	assert.Equal(t, uint64(1), tx.Nonce)
	assert.Equal(t, validator, tx.To)
	assert.Equal(t, big.NewInt(0), tx.Value) // Zero value for claiming rewards
	assert.Equal(t, fee, tx.Fee)
	assert.Equal(t, TxTypeClaimRewards, tx.Type)
	assert.Equal(t, []byte{}, tx.Data)
}

func TestBlockString(t *testing.T) {
	block := &Block{
		Header: BlockHeader{
			Height:    1,
			Timestamp: 1234567890,
		},
		Transactions: []Transaction{},
	}

	str := block.String()
	assert.Contains(t, str, "Block")
	assert.Contains(t, str, "Height: 1")
}

func TestTransactionString(t *testing.T) {
	tx := &Transaction{
		Nonce: 1,
		Value: big.NewInt(1000),
		Fee:   big.NewInt(10),
		Type:  TxTypeTransfer,
	}

	str := tx.String()
	assert.Contains(t, str, "Tx")
	assert.Contains(t, str, "Nonce: 1")
}

func TestTransactionMarshalJSON(t *testing.T) {
	tx := &Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Type:      TxTypeTransfer,
		Data:      []byte{},
		Timestamp: 1234567890,
	}

	jsonBytes, err := tx.MarshalJSON()
	require.NoError(t, err)

	// Verify JSON contains expected fields
	jsonStr := string(jsonBytes)
	assert.Contains(t, jsonStr, "nonce")
	assert.Contains(t, jsonStr, "value")
	assert.Contains(t, jsonStr, "fee")
	assert.Contains(t, jsonStr, "type")
}

func TestTransactionUnmarshalJSON(t *testing.T) {
	jsonStr := `{
		"nonce": 1,
		"to": "0000000000000000000000000000000000000000",
		"value": "1000",
		"fee": "10",
		"type": 0,
		"data": "",
		"timestamp": 1234567890
	}`

	var tx Transaction
	err := tx.UnmarshalJSON([]byte(jsonStr))
	require.NoError(t, err)

	assert.Equal(t, uint64(1), tx.Nonce)
	assert.Equal(t, big.NewInt(1000), tx.Value)
	assert.Equal(t, big.NewInt(10), tx.Fee)
	assert.Equal(t, TxTypeTransfer, tx.Type)
}

func TestTxTypeConstants(t *testing.T) {
	assert.Equal(t, TxType(0), TxTypeTransfer)
	assert.Equal(t, TxType(1), TxTypeStake)
	assert.Equal(t, TxType(2), TxTypeUnstake)
	assert.Equal(t, TxType(3), TxTypeDelegate)
	assert.Equal(t, TxType(4), TxTypeUndelegate)
	assert.Equal(t, TxType(5), TxTypeClaimRewards)
}

func TestMsgTypeConstants(t *testing.T) {
	assert.Equal(t, MsgType(0), MsgTypeProposal)
	assert.Equal(t, MsgType(1), MsgTypeApproval)
	assert.Equal(t, MsgType(2), MsgTypeTimeout)
}

func TestSignatureStruct(t *testing.T) {
	sig := Signature{
		V: 27,
		R: [32]byte{1, 2, 3},
		S: [32]byte{4, 5, 6},
	}

	assert.Equal(t, uint8(27), sig.V)
	assert.Equal(t, [32]byte{1, 2, 3}, sig.R)
	assert.Equal(t, [32]byte{4, 5, 6}, sig.S)
}

func TestAccountStruct(t *testing.T) {
	account := Account{
		Balance: big.NewInt(1000),
		Nonce:   5,
	}

	assert.Equal(t, big.NewInt(1000), account.Balance)
	assert.Equal(t, uint64(5), account.Nonce)
}

func TestDelegationStruct(t *testing.T) {
	delegator := crypto.Address{1, 2, 3}
	validator := crypto.Address{4, 5, 6}

	delegation := Delegation{
		Delegator:   delegator,
		Validator:   validator,
		Amount:      big.NewInt(1000),
		Rewards:     big.NewInt(50),
		LastClaimed: 1234567890,
	}

	assert.Equal(t, delegator, delegation.Delegator)
	assert.Equal(t, validator, delegation.Validator)
	assert.Equal(t, big.NewInt(1000), delegation.Amount)
	assert.Equal(t, big.NewInt(50), delegation.Rewards)
	assert.Equal(t, int64(1234567890), delegation.LastClaimed)
}

func TestConsensusMsgStruct(t *testing.T) {
	msg := ConsensusMsg{
		Height:    100,
		BlockHash: crypto.Hash{},
		Signature: []byte{1, 2, 3},
		Sender:    crypto.Address{},
		Type:      MsgTypeProposal,
	}

	assert.Equal(t, uint64(100), msg.Height)
	assert.Equal(t, crypto.Hash{}, msg.BlockHash)
	assert.Equal(t, []byte{1, 2, 3}, msg.Signature)
	assert.Equal(t, crypto.Address{}, msg.Sender)
	assert.Equal(t, MsgTypeProposal, msg.Type)
}
