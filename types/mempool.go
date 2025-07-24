package types

import (
	"container/heap"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"dyphira-node/crypto"
)

// Mempool represents the transaction memory pool
type Mempool struct {
	transactions map[crypto.Hash]*Transaction // tx hash -> transaction
	nonceMap     map[crypto.Address]uint64    // address -> highest nonce seen
	priorityHeap *TransactionHeap             // priority queue for transaction selection
	mu           sync.RWMutex
	maxSize      int
}

// TransactionHeap implements heap.Interface for priority queue
type TransactionHeap []*Transaction

func (h TransactionHeap) Len() int { return len(h) }

func (h TransactionHeap) Less(i, j int) bool {
	// Higher fee transactions have higher priority
	feeI := new(big.Int).Set(h[i].Fee)
	feeJ := new(big.Int).Set(h[j].Fee)

	if feeI.Cmp(feeJ) != 0 {
		return feeI.Cmp(feeJ) > 0 // Higher fee first
	}

	// If fees are equal, older transactions first
	return h[i].Timestamp < h[j].Timestamp
}

func (h TransactionHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *TransactionHeap) Push(x interface{}) {
	n := len(*h)
	tx := x.(*Transaction)
	tx.index = n
	*h = append(*h, tx)
}

func (h *TransactionHeap) Pop() interface{} {
	old := *h
	n := len(old)
	tx := old[n-1]
	old[n-1] = nil
	tx.index = -1
	*h = old[0 : n-1]
	return tx
}

// NewMempool creates a new mempool instance
func NewMempool(maxSize int) *Mempool {
	h := &TransactionHeap{}
	heap.Init(h)

	return &Mempool{
		transactions: make(map[crypto.Hash]*Transaction),
		nonceMap:     make(map[crypto.Address]uint64),
		priorityHeap: h,
		maxSize:      maxSize,
	}
}

// AddTransaction adds a transaction to the mempool
func (mp *Mempool) AddTransaction(tx *Transaction) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	txHash := tx.Hash()

	// Check if transaction already exists
	if _, exists := mp.transactions[txHash]; exists {
		return fmt.Errorf("transaction already exists in mempool")
	}

	// Check mempool size limit
	if len(mp.transactions) >= mp.maxSize {
		return fmt.Errorf("mempool is full")
	}

	// Set timestamp if not set
	if tx.Timestamp == 0 {
		tx.Timestamp = time.Now().Unix()
	}

	// Add to transactions map
	mp.transactions[txHash] = tx

	// Update nonce map
	sender, err := mp.getSenderAddress(tx)
	if err == nil {
		if currentNonce, exists := mp.nonceMap[sender]; !exists || tx.Nonce > currentNonce {
			mp.nonceMap[sender] = tx.Nonce
		}
	}

	// Add to priority heap
	heap.Push(mp.priorityHeap, tx)

	log.Printf("Added transaction to mempool: %s (fee: %s)", txHash.String(), tx.Fee.String())
	return nil
}

// GetPendingTransactions returns transactions for block inclusion
func (mp *Mempool) GetPendingTransactions(maxCount int, maxBlockSize int) []*Transaction {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	var selected []*Transaction
	currentSize := 0
	selectedCount := 0

	// Create a copy of the heap to avoid modifying the original
	tempHeap := &TransactionHeap{}
	*tempHeap = make([]*Transaction, mp.priorityHeap.Len())
	copy(*tempHeap, *mp.priorityHeap)
	heap.Init(tempHeap)

	for tempHeap.Len() > 0 && selectedCount < maxCount {
		tx := heap.Pop(tempHeap).(*Transaction)

		// Estimate transaction size (rough approximation)
		txBytes, err := tx.Bytes()
		if err != nil {
			log.Printf("Failed to get transaction bytes for size estimation: %v", err)
			continue
		}
		txSize := len(txBytes) + 65 // +65 for signature

		if currentSize+txSize > maxBlockSize {
			// Put transaction back and stop
			heap.Push(tempHeap, tx)
			break
		}

		selected = append(selected, tx)
		currentSize += txSize
		selectedCount++
	}

	log.Printf("Selected %d transactions for block (total size: %d bytes)", len(selected), currentSize)
	return selected
}

// RemoveTransactions removes transactions from mempool after block inclusion
func (mp *Mempool) RemoveTransactions(transactions []*Transaction) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	for _, tx := range transactions {
		txHash := tx.Hash()
		if _, exists := mp.transactions[txHash]; exists {
			delete(mp.transactions, txHash)
			log.Printf("Removed transaction from mempool: %s", txHash.String())
		}
	}

	// Rebuild priority heap
	mp.rebuildHeap()
}

// GetTransaction returns a transaction by hash
func (mp *Mempool) GetTransaction(hash crypto.Hash) (*Transaction, bool) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	tx, exists := mp.transactions[hash]
	return tx, exists
}

// GetSize returns the current mempool size
func (mp *Mempool) GetSize() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return len(mp.transactions)
}

// Clear removes all transactions from mempool
func (mp *Mempool) Clear() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.transactions = make(map[crypto.Hash]*Transaction)
	mp.nonceMap = make(map[crypto.Address]uint64)
	mp.priorityHeap = &TransactionHeap{}
	heap.Init(mp.priorityHeap)
}

// rebuildHeap rebuilds the priority heap from the transactions map
func (mp *Mempool) rebuildHeap() {
	mp.priorityHeap = &TransactionHeap{}
	heap.Init(mp.priorityHeap)

	for _, tx := range mp.transactions {
		heap.Push(mp.priorityHeap, tx)
	}
}

// getSenderAddress extracts sender address from transaction signature
func (mp *Mempool) getSenderAddress(tx *Transaction) (crypto.Address, error) {
	// Recreate transaction without signature
	txCopy := *tx
	txCopy.Signature = Signature{}
	txHash := txCopy.Hash()

	// Recover public key
	pubKey, err := crypto.Ecrecover(txHash[:], append(tx.Signature.R[:], tx.Signature.S[:]...), tx.Signature.V)
	if err != nil {
		return crypto.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}

	// Derive address
	address := crypto.PubToAddress(pubKey)
	return address, nil
}

// GetStats returns mempool statistics
func (mp *Mempool) GetStats() map[string]interface{} {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	totalFees := big.NewInt(0)
	for _, tx := range mp.transactions {
		totalFees.Add(totalFees, tx.Fee)
	}

	return map[string]interface{}{
		"size":           len(mp.transactions),
		"max_size":       mp.maxSize,
		"total_fees":     totalFees.String(),
		"unique_senders": len(mp.nonceMap),
	}
}
