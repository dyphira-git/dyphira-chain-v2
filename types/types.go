package types

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"dyphira-node/crypto"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// Block represents a Dyphira block
type Block struct {
	Header       BlockHeader   `json:"header"`
	Transactions []Transaction `json:"transactions"`
	ValidatorSig []byte        `json:"validator_sig"` // Proposer signature
	Approvals    [][]byte      `json:"approvals"`     // 21 validator signatures
}

// BlockHeader represents the header of a block
type BlockHeader struct {
	PrevHash           crypto.Hash    `json:"prev_hash"`
	Height             uint64         `json:"height"`
	Timestamp          int64          `json:"timestamp"`
	Proposer           crypto.Address `json:"proposer"`
	TxRoot             crypto.Hash    `json:"tx_root"`
	AccountStateRoot   crypto.Hash    `json:"account_state_root"`   // Core account state trie root
	ValidatorStateRoot crypto.Hash    `json:"validator_state_root"` // Participant tracker trie root
	TxStateRoot        crypto.Hash    `json:"tx_state_root"`        // Transaction tracker trie root
}

// Transaction represents a Dyphira transaction
type Transaction struct {
	Nonce     uint64         `json:"nonce"`
	To        crypto.Address `json:"to"`
	Value     *big.Int       `json:"value"`
	Fee       *big.Int       `json:"fee"`
	Signature Signature      `json:"signature"`
	Type      TxType         `json:"type"` // New field for transaction type
	Data      []byte         `json:"data"` // New field for transaction data
}

// TxType represents the type of transaction
type TxType uint8

const (
	TxTypeTransfer TxType = iota
	TxTypeStake
	TxTypeUnstake
	TxTypeDelegate
	TxTypeUndelegate
	TxTypeClaimRewards
)

// Signature represents transaction signature
type Signature struct {
	V uint8    `json:"v"`
	R [32]byte `json:"r"`
	S [32]byte `json:"s"`
}

// Validator represents a validator in the DPoS system
type Validator struct {
	Address        crypto.Address              `json:"address"`
	SelfStake      *big.Int                    `json:"self_stake"`
	DelegatedStake *big.Int                    `json:"delegated_stake"`
	Reputation     uint64                      `json:"reputation"`
	IsOnline       bool                        `json:"is_online"`
	LastSeen       int64                       `json:"last_seen"`
	Delegators     map[crypto.Address]*big.Int `json:"delegators"`      // Track individual delegators
	TotalRewards   *big.Int                    `json:"total_rewards"`   // Total rewards earned
	BlocksProposed uint64                      `json:"blocks_proposed"` // Number of blocks proposed
	BlocksApproved uint64                      `json:"blocks_approved"` // Number of blocks approved
}

// Delegation represents a delegation from a user to a validator
type Delegation struct {
	Delegator   crypto.Address `json:"delegator"`
	Validator   crypto.Address `json:"validator"`
	Amount      *big.Int       `json:"amount"`
	Rewards     *big.Int       `json:"rewards"`      // Accumulated rewards
	LastClaimed int64          `json:"last_claimed"` // Last time rewards were claimed
}

// Account represents a user account
type Account struct {
	Balance *big.Int `json:"balance"`
	Nonce   uint64   `json:"nonce"`
}

// ConsensusMsg represents a consensus message
type ConsensusMsg struct {
	Height    uint64         `json:"height"`
	BlockHash crypto.Hash    `json:"block_hash"`
	Signature []byte         `json:"signature"`
	Sender    crypto.Address `json:"sender"`
	Type      MsgType        `json:"type"`
}

// MsgType represents the type of consensus message
type MsgType uint8

const (
	MsgTypeProposal MsgType = iota
	MsgTypeApproval
	MsgTypeTimeout
)

// Block constants
const (
	CommitteeSize     = 5
	EpochLength       = 45
	BlockTime         = 2 * time.Second
	BlockSizeLimit    = 256 * 1024 * 1024 // 256 MB
	FinalityThreshold = 3                 // 2/3 + 1
	ApprovalTimeout   = 250 * time.Millisecond
	MinSelfStake      = 10000 // 10,000 DYP
	BlocksPerEpoch    = 9
)

// Hash calculates the hash of a block
func (b *Block) Hash() crypto.Hash {
	headerBytes := b.Header.Bytes()
	return crypto.CalculateHash(headerBytes)
}

// Bytes serializes the block header to bytes
func (bh *BlockHeader) Bytes() []byte {
	buf := make([]byte, 0, 200)

	// PrevHash (32 bytes)
	buf = append(buf, bh.PrevHash[:]...)

	// Height (8 bytes)
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, bh.Height)
	buf = append(buf, heightBytes...)

	// Timestamp (8 bytes)
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(bh.Timestamp))
	buf = append(buf, timestampBytes...)

	// Proposer (20 bytes)
	buf = append(buf, bh.Proposer[:]...)

	// TxRoot (32 bytes)
	buf = append(buf, bh.TxRoot[:]...)

	// AccountStateRoot (32 bytes)
	buf = append(buf, bh.AccountStateRoot[:]...)

	// ValidatorStateRoot (32 bytes)
	buf = append(buf, bh.ValidatorStateRoot[:]...)

	// TxStateRoot (32 bytes)
	buf = append(buf, bh.TxStateRoot[:]...)

	return buf
}

// Hash calculates the hash of a transaction
func (tx *Transaction) Hash() crypto.Hash {
	txBytes := tx.Bytes()
	return crypto.CalculateHash(txBytes)
}

// Bytes serializes the transaction to bytes (without signature)
func (tx *Transaction) Bytes() []byte {
	buf := make([]byte, 0, 100)

	// Nonce (8 bytes)
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, tx.Nonce)
	buf = append(buf, nonceBytes...)

	// To address (20 bytes)
	buf = append(buf, tx.To[:]...)

	// Value (variable length)
	valueBytes := tx.Value.Bytes()
	valueLen := len(valueBytes)
	if valueLen > 255 {
		panic("value too large")
	}
	buf = append(buf, byte(valueLen))
	buf = append(buf, valueBytes...)

	// Fee (variable length)
	feeBytes := tx.Fee.Bytes()
	feeLen := len(feeBytes)
	if feeLen > 255 {
		panic("fee too large")
	}
	buf = append(buf, byte(feeLen))
	buf = append(buf, feeBytes...)

	// Transaction type (1 byte)
	buf = append(buf, byte(tx.Type))

	// Data length and data (if any)
	dataLen := len(tx.Data)
	if dataLen > 65535 {
		panic("data too large")
	}
	dataLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(dataLenBytes, uint16(dataLen))
	buf = append(buf, dataLenBytes...)
	buf = append(buf, tx.Data...)

	return buf
}

// Sign signs a transaction with a key pair
func (tx *Transaction) Sign(keyPair *crypto.KeyPair) error {
	txHash := tx.Hash()
	sig, err := keyPair.SignHash(txHash)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	tx.Signature = Signature{
		V: sig.V,
		R: sig.R,
		S: sig.S,
	}

	return nil
}

// Verify verifies a transaction signature
func (tx *Transaction) Verify() bool {
	// Recreate the transaction without signature
	txCopy := *tx
	txCopy.Signature = Signature{}
	txHash := txCopy.Hash()

	// Recover public key from signature
	pubKey, err := crypto.Ecrecover(txHash[:], append(tx.Signature.R[:], tx.Signature.S[:]...), tx.Signature.V)
	if err != nil {
		return false
	}

	// Verify signature using the recovered public key
	// Convert signature to ECDSA format
	r := new(big.Int).SetBytes(tx.Signature.R[:])
	s := new(big.Int).SetBytes(tx.Signature.S[:])

	// Parse public key (pubKey is already compressed from Ecrecover)
	ecdsaPubKey, err := ethcrypto.DecompressPubkey(pubKey)
	if err != nil {
		return false
	}

	// Verify signature
	return ecdsa.Verify(ecdsaPubKey, txHash[:], r, s)
}

// GetTotalStake returns the total stake of a validator
func (v *Validator) GetTotalStake() *big.Int {
	total := new(big.Int)
	total.Add(v.SelfStake, v.DelegatedStake)
	return total
}

// NewStakeTransaction creates a new stake transaction
func NewStakeTransaction(nonce uint64, amount *big.Int, fee *big.Int) *Transaction {
	return &Transaction{
		Nonce: nonce,
		To:    crypto.Address{}, // Zero address for staking
		Value: amount,
		Fee:   fee,
		Type:  TxTypeStake,
		Data:  []byte{},
	}
}

// NewUnstakeTransaction creates a new unstake transaction
func NewUnstakeTransaction(nonce uint64, amount *big.Int, fee *big.Int) *Transaction {
	return &Transaction{
		Nonce: nonce,
		To:    crypto.Address{}, // Zero address for unstaking
		Value: amount,
		Fee:   fee,
		Type:  TxTypeUnstake,
		Data:  []byte{},
	}
}

// NewDelegateTransaction creates a new delegate transaction
func NewDelegateTransaction(nonce uint64, validator crypto.Address, amount *big.Int, fee *big.Int) *Transaction {
	return &Transaction{
		Nonce: nonce,
		To:    validator,
		Value: amount,
		Fee:   fee,
		Type:  TxTypeDelegate,
		Data:  []byte{},
	}
}

// NewUndelegateTransaction creates a new undelegate transaction
func NewUndelegateTransaction(nonce uint64, validator crypto.Address, amount *big.Int, fee *big.Int) *Transaction {
	return &Transaction{
		Nonce: nonce,
		To:    validator,
		Value: amount,
		Fee:   fee,
		Type:  TxTypeUndelegate,
		Data:  []byte{},
	}
}

// NewClaimRewardsTransaction creates a new claim rewards transaction
func NewClaimRewardsTransaction(nonce uint64, validator crypto.Address, fee *big.Int) *Transaction {
	return &Transaction{
		Nonce: nonce,
		To:    validator,
		Value: big.NewInt(0),
		Fee:   fee,
		Type:  TxTypeClaimRewards,
		Data:  []byte{},
	}
}

// IsEligible checks if a validator is eligible for committee
func (v *Validator) IsEligible() bool {
	return v.SelfStake.Cmp(big.NewInt(MinSelfStake)) >= 0 && v.IsOnline
}

// String returns string representation of block
func (b *Block) String() string {
	return fmt.Sprintf("Block{Height: %d, Hash: %s, Txs: %d}",
		b.Header.Height, b.Hash().String(), len(b.Transactions))
}

// String returns string representation of transaction
func (tx *Transaction) String() string {
	return fmt.Sprintf("Tx{Nonce: %d, To: %s, Value: %s}",
		tx.Nonce, tx.To.String(), tx.Value.String())
}

// MarshalJSON custom marshaling for big.Int
func (tx *Transaction) MarshalJSON() ([]byte, error) {
	type Alias Transaction
	return json.Marshal(&struct {
		Value string `json:"value"`
		Fee   string `json:"fee"`
		*Alias
	}{
		Value: tx.Value.String(),
		Fee:   tx.Fee.String(),
		Alias: (*Alias)(tx),
	})
}

// UnmarshalJSON custom unmarshaling for big.Int
func (tx *Transaction) UnmarshalJSON(data []byte) error {
	type Alias Transaction
	aux := &struct {
		Value string `json:"value"`
		Fee   string `json:"fee"`
		*Alias
	}{
		Alias: (*Alias)(tx),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	tx.Value = new(big.Int)
	if err := tx.Value.UnmarshalJSON(json.RawMessage(aux.Value)); err != nil {
		return err
	}
	tx.Fee = new(big.Int)
	if err := tx.Fee.UnmarshalJSON(json.RawMessage(aux.Fee)); err != nil {
		return err
	}
	return nil
}
