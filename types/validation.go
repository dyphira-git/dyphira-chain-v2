package types

import (
	"fmt"
	"math/big"
	"time"

	"dyphira-node/crypto"
)

// Validation errors
var (
	ErrInvalidAddress     = fmt.Errorf("invalid address")
	ErrInvalidAmount      = fmt.Errorf("invalid amount")
	ErrInvalidNonce       = fmt.Errorf("invalid nonce")
	ErrInvalidFee         = fmt.Errorf("invalid fee")
	ErrInvalidTimestamp   = fmt.Errorf("invalid timestamp")
	ErrInvalidBlockHeight = fmt.Errorf("invalid block height")
	ErrInvalidSignature   = fmt.Errorf("invalid signature")
	ErrInvalidData        = fmt.Errorf("invalid data")
	ErrInvalidStake       = fmt.Errorf("invalid stake amount")
	ErrInvalidReputation  = fmt.Errorf("invalid reputation")
)

// ValidateTransaction validates a transaction
func ValidateTransaction(tx *Transaction) error {
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}

	// Validate nonce
	if err := ValidateNonce(tx.Nonce); err != nil {
		return fmt.Errorf("invalid nonce: %w", err)
	}

	// Validate amount
	if err := ValidateAmount(tx.Value); err != nil {
		return fmt.Errorf("invalid value: %w", err)
	}

	// Validate fee
	if err := ValidateFee(tx.Fee); err != nil {
		return fmt.Errorf("invalid fee: %w", err)
	}

	// Validate timestamp
	if err := ValidateTimestamp(tx.Timestamp); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	// Validate data size
	if len(tx.Data) > 65535 {
		return fmt.Errorf("data too large: %d bytes (max 65535)", len(tx.Data))
	}

	// Validate transaction type
	if err := ValidateTxType(tx.Type); err != nil {
		return fmt.Errorf("invalid transaction type: %w", err)
	}

	return nil
}

// ValidateBlock validates a block
func ValidateBlock(block *Block) error {
	if block == nil {
		return fmt.Errorf("block cannot be nil")
	}

	// Validate header
	if err := ValidateBlockHeader(&block.Header); err != nil {
		return fmt.Errorf("invalid block header: %w", err)
	}

	// Validate transactions
	for i, tx := range block.Transactions {
		if err := ValidateTransaction(&tx); err != nil {
			return fmt.Errorf("invalid transaction at index %d: %w", i, err)
		}
	}

	// Validate validator signature
	if len(block.ValidatorSig) == 0 {
		return fmt.Errorf("missing validator signature")
	}

	// Validate approvals
	if len(block.Approvals) > 21 {
		return fmt.Errorf("too many approvals: %d (max 21)", len(block.Approvals))
	}

	for i, approval := range block.Approvals {
		if len(approval) == 0 {
			return fmt.Errorf("empty approval at index %d", i)
		}
	}

	return nil
}

// ValidateBlockHeader validates a block header
func ValidateBlockHeader(header *BlockHeader) error {
	if header == nil {
		return fmt.Errorf("block header cannot be nil")
	}

	// Validate height
	if err := ValidateBlockHeight(header.Height); err != nil {
		return fmt.Errorf("invalid height: %w", err)
	}

	// Validate timestamp
	if err := ValidateTimestamp(header.Timestamp); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	// Validate proposer address
	if err := ValidateAddress(header.Proposer); err != nil {
		return fmt.Errorf("invalid proposer address: %w", err)
	}

	return nil
}

// ValidateValidator validates a validator
func ValidateValidator(validator *Validator) error {
	if validator == nil {
		return fmt.Errorf("validator cannot be nil")
	}

	// Validate address
	if err := ValidateAddress(validator.Address); err != nil {
		return fmt.Errorf("invalid validator address: %w", err)
	}

	// Validate self stake
	if err := ValidateStake(validator.SelfStake); err != nil {
		return fmt.Errorf("invalid self stake: %w", err)
	}

	// Validate delegated stake
	if err := ValidateStake(validator.DelegatedStake); err != nil {
		return fmt.Errorf("invalid delegated stake: %w", err)
	}

	// Validate reputation
	if err := ValidateReputation(validator.Reputation); err != nil {
		return fmt.Errorf("invalid reputation: %w", err)
	}

	// Validate last seen timestamp
	if err := ValidateTimestamp(validator.LastSeen); err != nil {
		return fmt.Errorf("invalid last seen timestamp: %w", err)
	}

	// Validate total rewards
	if err := ValidateAmount(validator.TotalRewards); err != nil {
		return fmt.Errorf("invalid total rewards: %w", err)
	}

	return nil
}

// ValidateAccount validates an account
func ValidateAccount(account *Account) error {
	if account == nil {
		return fmt.Errorf("account cannot be nil")
	}

	// Validate balance
	if err := ValidateAmount(account.Balance); err != nil {
		return fmt.Errorf("invalid balance: %w", err)
	}

	return nil
}

// ValidateDelegation validates a delegation
func ValidateDelegation(delegation *Delegation) error {
	if delegation == nil {
		return fmt.Errorf("delegation cannot be nil")
	}

	// Validate delegator address
	if err := ValidateAddress(delegation.Delegator); err != nil {
		return fmt.Errorf("invalid delegator address: %w", err)
	}

	// Validate validator address
	if err := ValidateAddress(delegation.Validator); err != nil {
		return fmt.Errorf("invalid validator address: %w", err)
	}

	// Validate amount
	if err := ValidateStake(delegation.Amount); err != nil {
		return fmt.Errorf("invalid delegation amount: %w", err)
	}

	// Validate rewards
	if err := ValidateAmount(delegation.Rewards); err != nil {
		return fmt.Errorf("invalid rewards: %w", err)
	}

	// Validate last claimed timestamp
	if err := ValidateTimestamp(delegation.LastClaimed); err != nil {
		return fmt.Errorf("invalid last claimed timestamp: %w", err)
	}

	return nil
}

// ValidateConsensusMsg validates a consensus message
func ValidateConsensusMsg(msg *ConsensusMsg) error {
	if msg == nil {
		return fmt.Errorf("consensus message cannot be nil")
	}

	// Validate height
	if err := ValidateBlockHeight(msg.Height); err != nil {
		return fmt.Errorf("invalid height: %w", err)
	}

	// Validate sender address
	if err := ValidateAddress(msg.Sender); err != nil {
		return fmt.Errorf("invalid sender address: %w", err)
	}

	// Validate signature
	if len(msg.Signature) == 0 {
		return fmt.Errorf("missing signature")
	}

	// Validate message type
	if err := ValidateMsgType(msg.Type); err != nil {
		return fmt.Errorf("invalid message type: %w", err)
	}

	return nil
}

// ValidateAddress validates an address
func ValidateAddress(address crypto.Address) error {
	if address == (crypto.Address{}) {
		return ErrInvalidAddress
	}
	return nil
}

// ValidateAmount validates an amount (must be non-negative)
func ValidateAmount(amount *big.Int) error {
	if amount == nil {
		return ErrInvalidAmount
	}
	if amount.Sign() < 0 {
		return ErrInvalidAmount
	}
	return nil
}

// ValidateStake validates a stake amount (must be positive)
func ValidateStake(stake *big.Int) error {
	if stake == nil {
		return ErrInvalidStake
	}
	if stake.Sign() <= 0 {
		return ErrInvalidStake
	}
	return nil
}

// ValidateNonce validates a nonce
func ValidateNonce(nonce uint64) error {
	// Nonce can be any non-negative integer
	return nil
}

// ValidateFee validates a fee (must be non-negative)
func ValidateFee(fee *big.Int) error {
	if fee == nil {
		return ErrInvalidFee
	}
	if fee.Sign() < 0 {
		return ErrInvalidFee
	}
	return nil
}

// ValidateTimestamp validates a timestamp
func ValidateTimestamp(timestamp int64) error {
	// Timestamp should be reasonable (not too far in past or future)
	now := time.Now().Unix()
	if timestamp < now-31536000 { // 1 year ago
		return ErrInvalidTimestamp
	}
	if timestamp > now+31536000 { // 1 year in future
		return ErrInvalidTimestamp
	}
	return nil
}

// ValidateBlockHeight validates a block height
func ValidateBlockHeight(height uint64) error {
	// Block height can be any non-negative integer
	return nil
}

// ValidateReputation validates a reputation score
func ValidateReputation(reputation uint64) error {
	// Reputation can be any non-negative integer
	return nil
}

// ValidateTxType validates a transaction type
func ValidateTxType(txType TxType) error {
	switch txType {
	case TxTypeTransfer, TxTypeStake, TxTypeUnstake, TxTypeDelegate, TxTypeUndelegate, TxTypeClaimRewards:
		return nil
	default:
		return fmt.Errorf("unknown transaction type: %d", txType)
	}
}

// ValidateMsgType validates a message type
func ValidateMsgType(msgType MsgType) error {
	switch msgType {
	case MsgTypeProposal, MsgTypeApproval, MsgTypeTimeout:
		return nil
	default:
		return fmt.Errorf("unknown message type: %d", msgType)
	}
}

// ValidateSignature validates a signature
func ValidateSignature(sig *Signature) error {
	if sig == nil {
		return ErrInvalidSignature
	}

	// Validate V value (should be 27 or 28 for Ethereum-style signatures)
	if sig.V != 27 && sig.V != 28 {
		return ErrInvalidSignature
	}

	// Validate R and S values (should not be zero)
	if sig.R == [32]byte{} {
		return ErrInvalidSignature
	}
	if sig.S == [32]byte{} {
		return ErrInvalidSignature
	}

	return nil
}

// ValidateData validates data
func ValidateData(data []byte) error {
	if data == nil {
		return nil // nil data is valid
	}
	if len(data) > 65535 {
		return ErrInvalidData
	}
	return nil
}
