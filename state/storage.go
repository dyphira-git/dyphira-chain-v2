package state

import (
	"encoding/json"
	"fmt"

	"dyphira-node/crypto"
	"dyphira-node/types"

	"github.com/syndtr/goleveldb/leveldb"
)

// Storage represents the blockchain storage layer for blocks and metadata
// Note: Account and validator data is now handled by StateMachines
type Storage struct {
	db *leveldb.DB
}

// NewStorage creates a new storage instance
func NewStorage(dbPath string) (*Storage, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	return &Storage{db: db}, nil
}

// Close closes the storage
func (s *Storage) Close() error {
	return s.db.Close()
}

// Storage keys
const (
	// Block storage
	BlockPrefix     = "block:"
	BlockHashPrefix = "blockhash:"

	// Transaction storage (for block-level transaction storage)
	TxPrefix = "tx:"

	// Chain metadata
	LatestBlockKey = "latest_block"
	GenesisKey     = "genesis"
)

// StoreBlock stores a block
func (s *Storage) StoreBlock(block *types.Block) error {
	// Store block by height
	heightKey := fmt.Sprintf("%s%d", BlockPrefix, block.Header.Height)
	blockData, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}

	err = s.db.Put([]byte(heightKey), blockData, nil)
	if err != nil {
		return fmt.Errorf("failed to store block: %w", err)
	}

	// Store block by hash
	blockHash := block.Hash()
	hashKey := fmt.Sprintf("%s%s", BlockHashPrefix, blockHash.String())
	err = s.db.Put([]byte(hashKey), []byte(fmt.Sprintf("%d", block.Header.Height)), nil)
	if err != nil {
		return fmt.Errorf("failed to store block hash: %w", err)
	}

	// Store transactions (for block-level access)
	for _, tx := range block.Transactions {
		txHash := tx.Hash()
		txKey := fmt.Sprintf("%s%s", TxPrefix, txHash.String())
		txData, err := json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("failed to marshal transaction: %w", err)
		}

		err = s.db.Put([]byte(txKey), txData, nil)
		if err != nil {
			return fmt.Errorf("failed to store transaction: %w", err)
		}
	}

	return nil
}

// GetBlockByHeight retrieves a block by height
func (s *Storage) GetBlockByHeight(height uint64) (*types.Block, error) {
	heightKey := fmt.Sprintf("%s%d", BlockPrefix, height)
	blockData, err := s.db.Get([]byte(heightKey), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return nil, fmt.Errorf("block not found at height %d", height)
		}
		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	var block types.Block
	err = json.Unmarshal(blockData, &block)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal block: %w", err)
	}

	return &block, nil
}

// GetBlockByHash retrieves a block by hash
func (s *Storage) GetBlockByHash(hash crypto.Hash) (*types.Block, error) {
	hashKey := fmt.Sprintf("%s%s", BlockHashPrefix, hash.String())
	heightData, err := s.db.Get([]byte(hashKey), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return nil, fmt.Errorf("block not found with hash %s", hash.String())
		}
		return nil, fmt.Errorf("failed to get block hash: %w", err)
	}

	// Parse height and get block
	heightStr := string(heightData)
	var height uint64
	_, err = fmt.Sscanf(heightStr, "%d", &height)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block height: %w", err)
	}

	return s.GetBlockByHeight(height)
}

// GetTransaction retrieves a transaction by hash (from block storage)
func (s *Storage) GetTransaction(hash crypto.Hash) (*types.Transaction, error) {
	txKey := fmt.Sprintf("%s%s", TxPrefix, hash.String())
	txData, err := s.db.Get([]byte(txKey), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return nil, fmt.Errorf("transaction not found with hash %s", hash.String())
		}
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	var tx types.Transaction
	err = json.Unmarshal(txData, &tx)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	return &tx, nil
}

// SetLatestBlock sets the latest block height
func (s *Storage) SetLatestBlock(height uint64) error {
	heightData := fmt.Sprintf("%d", height)
	err := s.db.Put([]byte(LatestBlockKey), []byte(heightData), nil)
	if err != nil {
		return fmt.Errorf("failed to set latest block: %w", err)
	}
	return nil
}

// GetLatestBlock gets the latest block height
func (s *Storage) GetLatestBlock() (uint64, error) {
	heightData, err := s.db.Get([]byte(LatestBlockKey), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return 0, nil // Genesis block
		}
		return 0, fmt.Errorf("failed to get latest block: %w", err)
	}

	// Parse height
	heightStr := string(heightData)
	var height uint64
	_, err = fmt.Sscanf(heightStr, "%d", &height)
	if err != nil {
		return 0, fmt.Errorf("failed to parse latest block height: %w", err)
	}

	return height, nil
}

// StoreGenesis stores the genesis block
func (s *Storage) StoreGenesis(block *types.Block) error {
	genesisData, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal genesis block: %w", err)
	}

	err = s.db.Put([]byte(GenesisKey), genesisData, nil)
	if err != nil {
		return fmt.Errorf("failed to store genesis block: %w", err)
	}

	return nil
}

// GetGenesis retrieves the genesis block
func (s *Storage) GetGenesis() (*types.Block, error) {
	genesisData, err := s.db.Get([]byte(GenesisKey), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return nil, fmt.Errorf("genesis block not found")
		}
		return nil, fmt.Errorf("failed to get genesis block: %w", err)
	}

	var block types.Block
	err = json.Unmarshal(genesisData, &block)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal genesis block: %w", err)
	}

	return &block, nil
}

// DeleteBlock deletes a block and its transactions
func (s *Storage) DeleteBlock(height uint64) error {
	// Get the block first
	block, err := s.GetBlockByHeight(height)
	if err != nil {
		return fmt.Errorf("failed to get block for deletion: %w", err)
	}

	// Delete block by height
	heightKey := fmt.Sprintf("%s%d", BlockPrefix, height)
	err = s.db.Delete([]byte(heightKey), nil)
	if err != nil {
		return fmt.Errorf("failed to delete block: %w", err)
	}

	// Delete block by hash
	blockHash := block.Hash()
	hashKey := fmt.Sprintf("%s%s", BlockHashPrefix, blockHash.String())
	err = s.db.Delete([]byte(hashKey), nil)
	if err != nil {
		return fmt.Errorf("failed to delete block hash: %w", err)
	}

	// Delete transactions
	for _, tx := range block.Transactions {
		txHash := tx.Hash()
		txKey := fmt.Sprintf("%s%s", TxPrefix, txHash.String())
		err = s.db.Delete([]byte(txKey), nil)
		if err != nil {
			return fmt.Errorf("failed to delete transaction: %w", err)
		}
	}

	return nil
}
