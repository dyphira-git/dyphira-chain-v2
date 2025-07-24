package state

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"dyphira-node/crypto"
)

// Trie represents a binary Merkle Trie
type Trie struct {
	root *Node
	db   *TrieDB
}

// Node represents a trie node
type Node struct {
	Hash     crypto.Hash
	Children [2]*Node // Binary children
	Value    []byte
	IsLeaf   bool
}

// TrieDB represents the trie database
type TrieDB struct {
	nodes map[crypto.Hash]*Node
}

// NewTrie creates a new trie
func NewTrie() *Trie {
	return &Trie{
		root: &Node{},
		db:   &TrieDB{nodes: make(map[crypto.Hash]*Node)},
	}
}

// AccountKey generates the key for an account balance (D_b)
// Uses HASH(D_a)[0...253] + 0b00 as per EIP-3102 specification
func AccountKey(address crypto.Address) []byte {
	hash := crypto.CalculateHash(address[:])
	// Take first 254 bits (31.75 bytes) and add 0b00 suffix
	// This gives us 256 bits total (32 bytes)
	key := make([]byte, 32)
	copy(key[:31], hash[:31])
	key[31] = (hash[31] & 0xFC) // Clear last 2 bits and set to 0b00
	return key
}

// NonceKey generates the key for an account nonce (D_n)
// Uses HASH(D_a)[0...253] + 0b01 as per EIP-3102 specification
func NonceKey(address crypto.Address) []byte {
	hash := crypto.CalculateHash(address[:])
	// Take first 254 bits (31.75 bytes) and add 0b01 suffix
	key := make([]byte, 32)
	copy(key[:31], hash[:31])
	key[31] = (hash[31] & 0xFC) | 0x01 // Clear last 2 bits and set to 0b01
	return key
}

// ValidatorKey generates the key for a validator (V_b)
// Uses HASH(D_a)[0...253] + 0b10 for validator data
func ValidatorKey(address crypto.Address) []byte {
	hash := crypto.CalculateHash(address[:])
	// Take first 254 bits (31.75 bytes) and add 0b10 suffix
	key := make([]byte, 32)
	copy(key[:31], hash[:31])
	key[31] = (hash[31] & 0xFC) | 0x02 // Clear last 2 bits and set to 0b10
	return key
}

// Get retrieves a value from the trie
func (t *Trie) Get(key []byte) ([]byte, bool) {
	if t.root == nil {
		return nil, false
	}

	node := t.root
	keyBits := bytesToBits(key)

	for i := 0; i < len(keyBits); i++ {
		if node == nil {
			return nil, false
		}

		if node.IsLeaf {
			// Check if this is the leaf we're looking for
			if bytes.Equal(node.Value[:len(key)], key) {
				return node.Value[len(key):], true
			}
			return nil, false
		}

		bit := keyBits[i]
		if bit == 0 {
			node = node.Children[0]
		} else {
			node = node.Children[1]
		}
	}

	if node != nil && node.IsLeaf {
		return node.Value, true
	}

	return nil, false
}

// Put stores a value in the trie
func (t *Trie) Put(key, value []byte) error {
	if t.root == nil {
		t.root = &Node{}
	}

	keyBits := bytesToBits(key)
	t.root = t.putNode(t.root, key, value, keyBits, 0)
	return nil
}

// putNode recursively puts a value in the trie
func (t *Trie) putNode(node *Node, key, value []byte, keyBits []int, depth int) *Node {
	if node == nil {
		node = &Node{}
	}

	if depth == len(keyBits) {
		// Leaf node
		node.IsLeaf = true
		node.Value = append(key, value...)
		node.Children = [2]*Node{nil, nil}
	} else {
		// Internal node
		bit := keyBits[depth]
		if bit == 0 {
			node.Children[0] = t.putNode(node.Children[0], key, value, keyBits, depth+1)
		} else {
			node.Children[1] = t.putNode(node.Children[1], key, value, keyBits, depth+1)
		}
		node.IsLeaf = false
	}

	// Update hash
	node.Hash = t.calculateNodeHash(node)
	return node
}

// Delete removes a value from the trie
func (t *Trie) Delete(key []byte) error {
	if t.root == nil {
		return nil
	}

	keyBits := bytesToBits(key)
	t.root = t.deleteNode(t.root, key, keyBits, 0)
	return nil
}

// deleteNode recursively deletes a value from the trie
func (t *Trie) deleteNode(node *Node, key []byte, keyBits []int, depth int) *Node {
	if node == nil {
		return nil
	}

	if depth == len(keyBits) {
		// Found the leaf to delete
		return nil
	}

	bit := keyBits[depth]
	if bit == 0 {
		node.Children[0] = t.deleteNode(node.Children[0], key, keyBits, depth+1)
	} else {
		node.Children[1] = t.deleteNode(node.Children[1], key, keyBits, depth+1)
	}

	// If both children are nil, this node becomes nil
	if node.Children[0] == nil && node.Children[1] == nil {
		return nil
	}

	// Update hash
	node.Hash = t.calculateNodeHash(node)
	return node
}

// calculateNodeHash calculates the hash of a node
func (t *Trie) calculateNodeHash(node *Node) crypto.Hash {
	if node == nil {
		return crypto.Hash{}
	}

	if node.IsLeaf {
		// Hash the value
		return crypto.CalculateHash(node.Value)
	}

	// Hash the children
	var data []byte
	if node.Children[0] != nil {
		data = append(data, node.Children[0].Hash[:]...)
	} else {
		data = append(data, make([]byte, 32)...)
	}

	if node.Children[1] != nil {
		data = append(data, node.Children[1].Hash[:]...)
	} else {
		data = append(data, make([]byte, 32)...)
	}

	return crypto.CalculateHash(data)
}

// Root returns the root hash of the trie
func (t *Trie) Root() crypto.Hash {
	if t.root == nil {
		return crypto.Hash{}
	}
	return t.root.Hash
}

// bytesToBits converts bytes to bits
func bytesToBits(data []byte) []int {
	bits := make([]int, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = int((b >> (7 - j)) & 1)
		}
	}
	return bits
}

// Account represents an account in the state
type Account struct {
	Balance *big.Int
	Nonce   uint64
}

// EncodeAccount encodes an account to bytes
func EncodeAccount(account *Account) ([]byte, error) {
	var buf []byte

	// Encode balance
	balanceBytes := account.Balance.Bytes()
	balanceLen := len(balanceBytes)
	if balanceLen > 255 {
		return nil, fmt.Errorf("balance too large: %d bytes (max 255)", balanceLen)
	}
	buf = append(buf, byte(balanceLen))
	buf = append(buf, balanceBytes...)

	// Encode nonce (8 bytes)
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, account.Nonce)
	buf = append(buf, nonceBytes...)

	return buf, nil
}

// DecodeAccount decodes an account from bytes
func DecodeAccount(data []byte) (*Account, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("invalid account data length")
	}

	// Decode balance
	balanceLen := int(data[0])
	if len(data) < 1+balanceLen+8 {
		return nil, fmt.Errorf("invalid account data length")
	}

	balance := new(big.Int).SetBytes(data[1 : 1+balanceLen])

	// Decode nonce
	nonceBytes := data[1+balanceLen : 1+balanceLen+8]
	nonce := binary.BigEndian.Uint64(nonceBytes)

	return &Account{
		Balance: balance,
		Nonce:   nonce,
	}, nil
}

// Validator represents a validator in the state
type Validator struct {
	Address        crypto.Address
	SelfStake      *big.Int
	DelegatedStake *big.Int
	Reputation     uint64
	IsOnline       bool
	LastSeen       int64
	Delegators     map[crypto.Address]*big.Int
	TotalRewards   *big.Int
	BlocksProposed uint64
	BlocksApproved uint64
}

// EncodeValidator encodes a validator to bytes
func EncodeValidator(validator *Validator) ([]byte, error) {
	var buf []byte

	// Encode address (20 bytes)
	buf = append(buf, validator.Address[:]...)

	// Encode self stake
	selfStakeBytes := validator.SelfStake.Bytes()
	selfStakeLen := len(selfStakeBytes)
	if selfStakeLen > 255 {
		return nil, fmt.Errorf("self stake too large: %d bytes (max 255)", selfStakeLen)
	}
	buf = append(buf, byte(selfStakeLen))
	buf = append(buf, selfStakeBytes...)

	// Encode delegated stake
	delegatedStakeBytes := validator.DelegatedStake.Bytes()
	delegatedStakeLen := len(delegatedStakeBytes)
	if delegatedStakeLen > 255 {
		return nil, fmt.Errorf("delegated stake too large: %d bytes (max 255)", delegatedStakeLen)
	}
	buf = append(buf, byte(delegatedStakeLen))
	buf = append(buf, delegatedStakeBytes...)

	// Encode reputation (8 bytes)
	reputationBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(reputationBytes, validator.Reputation)
	buf = append(buf, reputationBytes...)

	// Encode is online (1 byte)
	if validator.IsOnline {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// Encode last seen (8 bytes)
	lastSeenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lastSeenBytes, uint64(validator.LastSeen))
	buf = append(buf, lastSeenBytes...)

	// Encode total rewards
	totalRewardsBytes := validator.TotalRewards.Bytes()
	totalRewardsLen := len(totalRewardsBytes)
	if totalRewardsLen > 255 {
		return nil, fmt.Errorf("total rewards too large: %d bytes (max 255)", totalRewardsLen)
	}
	buf = append(buf, byte(totalRewardsLen))
	buf = append(buf, totalRewardsBytes...)

	// Encode blocks proposed (8 bytes)
	blocksProposedBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blocksProposedBytes, validator.BlocksProposed)
	buf = append(buf, blocksProposedBytes...)

	// Encode blocks approved (8 bytes)
	blocksApprovedBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blocksApprovedBytes, validator.BlocksApproved)
	buf = append(buf, blocksApprovedBytes...)

	// Note: Delegators map is not encoded as it's handled separately in the state machines

	return buf, nil
}

// DecodeValidator decodes a validator from bytes
func DecodeValidator(data []byte) (*Validator, error) {
	if len(data) < 38 {
		return nil, fmt.Errorf("invalid validator data length")
	}

	pos := 0

	// Decode address (20 bytes)
	var address crypto.Address
	copy(address[:], data[pos:pos+20])
	pos += 20

	// Decode self stake
	selfStakeLen := int(data[pos])
	pos++
	if len(data) < pos+selfStakeLen {
		return nil, fmt.Errorf("invalid validator data length")
	}
	selfStake := new(big.Int).SetBytes(data[pos : pos+selfStakeLen])
	pos += selfStakeLen

	// Decode delegated stake
	delegatedStakeLen := int(data[pos])
	pos++
	if len(data) < pos+delegatedStakeLen {
		return nil, fmt.Errorf("invalid validator data length")
	}
	delegatedStake := new(big.Int).SetBytes(data[pos : pos+delegatedStakeLen])
	pos += delegatedStakeLen

	// Decode reputation
	if len(data) < pos+8 {
		return nil, fmt.Errorf("invalid validator data length")
	}
	reputation := binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8

	// Decode is online
	if len(data) < pos+1 {
		return nil, fmt.Errorf("invalid validator data length")
	}
	isOnline := data[pos] == 1
	pos++

	// Decode last seen
	if len(data) < pos+8 {
		return nil, fmt.Errorf("invalid validator data length")
	}
	lastSeen := int64(binary.BigEndian.Uint64(data[pos : pos+8]))
	pos += 8

	// Decode total rewards
	if len(data) < pos+1 {
		return nil, fmt.Errorf("invalid validator data length")
	}
	totalRewardsLen := int(data[pos])
	pos++
	if len(data) < pos+totalRewardsLen {
		return nil, fmt.Errorf("invalid validator data length")
	}
	totalRewards := new(big.Int).SetBytes(data[pos : pos+totalRewardsLen])
	pos += totalRewardsLen

	// Decode blocks proposed
	if len(data) < pos+8 {
		return nil, fmt.Errorf("invalid validator data length")
	}
	blocksProposed := binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8

	// Decode blocks approved
	if len(data) < pos+8 {
		return nil, fmt.Errorf("invalid validator data length")
	}
	blocksApproved := binary.BigEndian.Uint64(data[pos : pos+8])

	return &Validator{
		Address:        address,
		SelfStake:      selfStake,
		DelegatedStake: delegatedStake,
		Reputation:     reputation,
		IsOnline:       isOnline,
		LastSeen:       lastSeen,
		TotalRewards:   totalRewards,
		BlocksProposed: blocksProposed,
		BlocksApproved: blocksApproved,
		Delegators:     make(map[crypto.Address]*big.Int), // Initialize empty map
	}, nil
}
