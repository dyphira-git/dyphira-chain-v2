package types

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"dyphira-node/crypto"
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
}

// Signature represents transaction signature
type Signature struct {
	V uint8    `json:"v"`
	R [32]byte `json:"r"`
	S [32]byte `json:"s"`
}

// Validator represents a validator in the DPoS system
type Validator struct {
	Address        crypto.Address `json:"address"`
	SelfStake      *big.Int       `json:"self_stake"`
	DelegatedStake *big.Int       `json:"delegated_stake"`
	Reputation     uint64         `json:"reputation"`
	IsOnline       bool           `json:"is_online"`
	LastSeen       int64          `json:"last_seen"`
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
	CommitteeSize     = 31
	EpochLength       = 270
	BlockTime         = 2 * time.Second
	BlockSizeLimit    = 256 * 1024 * 1024 // 256 MB
	FinalityThreshold = 21                // 2/3 + 1
	ApprovalTimeout   = 250 * time.Millisecond
	MinSelfStake      = 10000 // 10,000 DYP
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

	// Verify signature
	return crypto.VerifySignature(txHash, &crypto.Signature{
		V: tx.Signature.V,
		R: tx.Signature.R,
		S: tx.Signature.S,
	}, pubKey)
}

// GetTotalStake returns the total stake of a validator
func (v *Validator) GetTotalStake() *big.Int {
	total := new(big.Int)
	total.Add(v.SelfStake, v.DelegatedStake)
	return total
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

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Parse big.Int values
	value, ok := new(big.Int).SetString(aux.Value, 10)
	if !ok {
		return fmt.Errorf("invalid value: %s", aux.Value)
	}
	tx.Value = value

	fee, ok := new(big.Int).SetString(aux.Fee, 10)
	if !ok {
		return fmt.Errorf("invalid fee: %s", aux.Fee)
	}
	tx.Fee = fee

	return nil
}
