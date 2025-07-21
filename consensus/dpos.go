package consensus

import (
	"fmt"
	"math/big"
	"sort"
	"time"

	"dyphira-node/crypto"
	"dyphira-node/types"
)

// DPoS represents the DPoS consensus engine
type DPoS struct {
	validators    []*types.Validator
	committee     []*types.Validator
	currentEpoch  uint64
	blockHeight   uint64
	lastEpochTime int64
}

// NewDPoS creates a new DPoS consensus engine
func NewDPoS() *DPoS {
	return &DPoS{
		validators:    make([]*types.Validator, 0),
		committee:     make([]*types.Validator, 0),
		currentEpoch:  0,
		blockHeight:   0,
		lastEpochTime: time.Now().Unix(),
	}
}

// AddValidator adds a validator to the system
func (d *DPoS) AddValidator(validator *types.Validator) error {
	// Check if validator already exists
	for _, v := range d.validators {
		if v.Address == validator.Address {
			return fmt.Errorf("validator already exists: %s", validator.Address.String())
		}
	}

	d.validators = append(d.validators, validator)
	return nil
}

// RemoveValidator removes a validator from the system
func (d *DPoS) RemoveValidator(address crypto.Address) error {
	for i, v := range d.validators {
		if v.Address == address {
			d.validators = append(d.validators[:i], d.validators[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("validator not found: %s", address.String())
}

// UpdateValidator updates a validator's information
func (d *DPoS) UpdateValidator(address crypto.Address, updates *types.Validator) error {
	for _, v := range d.validators {
		if v.Address == address {
			v.SelfStake = updates.SelfStake
			v.DelegatedStake = updates.DelegatedStake
			v.Reputation = updates.Reputation
			v.IsOnline = updates.IsOnline
			v.LastSeen = updates.LastSeen
			return nil
		}
	}
	return fmt.Errorf("validator not found: %s", address.String())
}

// ElectCommittee elects the committee for the current epoch
func (d *DPoS) ElectCommittee() error {
	// Filter eligible validators
	var eligible []*types.Validator
	for _, v := range d.validators {
		if v.IsEligible() {
			eligible = append(eligible, v)
		}
	}

	if len(eligible) < types.CommitteeSize {
		return fmt.Errorf("insufficient eligible validators: %d < %d", len(eligible), types.CommitteeSize)
	}

	// Sort by total stake * reputation
	sort.Slice(eligible, func(i, j int) bool {
		totalStakeI := eligible[i].GetTotalStake()
		totalStakeJ := eligible[j].GetTotalStake()

		scoreI := new(big.Int).Mul(totalStakeI, big.NewInt(int64(eligible[i].Reputation)))
		scoreJ := new(big.Int).Mul(totalStakeJ, big.NewInt(int64(eligible[j].Reputation)))

		return scoreI.Cmp(scoreJ) > 0
	})

	// Select top 31 validators
	d.committee = eligible[:types.CommitteeSize]
	return nil
}

// GetCommittee returns the current committee
func (d *DPoS) GetCommittee() []*types.Validator {
	return d.committee
}

// GetProposer returns the proposer for the current block
func (d *DPoS) GetProposer() (*types.Validator, error) {
	if len(d.committee) == 0 {
		return nil, fmt.Errorf("no committee elected")
	}

	// Calculate proposer index based on block height
	proposerIndex := (d.blockHeight / 9) % uint64(len(d.committee))
	return d.committee[proposerIndex], nil
}

// ShouldStartNewEpoch checks if a new epoch should start
func (d *DPoS) ShouldStartNewEpoch() bool {
	return d.blockHeight%types.EpochLength == 0
}

// StartNewEpoch starts a new epoch
func (d *DPoS) StartNewEpoch() error {
	d.currentEpoch++
	d.lastEpochTime = time.Now().Unix()

	// Elect new committee
	err := d.ElectCommittee()
	if err != nil {
		return fmt.Errorf("failed to elect committee: %w", err)
	}

	return nil
}

// ProcessBlock processes a block and updates consensus state
func (d *DPoS) ProcessBlock(block *types.Block) error {
	// Update block height
	d.blockHeight = block.Header.Height

	// Check if new epoch should start
	if d.ShouldStartNewEpoch() {
		err := d.StartNewEpoch()
		if err != nil {
			return fmt.Errorf("failed to start new epoch: %w", err)
		}
	}

	return nil
}

// ValidateBlock validates a block from consensus perspective
func (d *DPoS) ValidateBlock(block *types.Block) error {
	// Check if proposer is in committee
	proposer, err := d.GetProposer()
	if err != nil {
		return fmt.Errorf("failed to get proposer: %w", err)
	}

	if block.Header.Proposer != proposer.Address {
		return fmt.Errorf("invalid proposer: expected %s, got %s",
			proposer.Address.String(), block.Header.Proposer.String())
	}

	// Check number of approvals
	if len(block.Approvals) < types.FinalityThreshold {
		return fmt.Errorf("insufficient approvals: %d < %d", len(block.Approvals), types.FinalityThreshold)
	}

	// Validate approvals
	approvalCount := 0
	for range block.Approvals {
		// Verify approval signature
		// This is a simplified version - in practice you'd verify each signature
		approvalCount++
	}

	if approvalCount < types.FinalityThreshold {
		return fmt.Errorf("insufficient valid approvals: %d < %d", approvalCount, types.FinalityThreshold)
	}

	return nil
}

// CreateBlock creates a new block
func (d *DPoS) CreateBlock(transactions []types.Transaction, proposerKeyPair *crypto.KeyPair) (*types.Block, error) {
	// Get current proposer
	proposer, err := d.GetProposer()
	if err != nil {
		return nil, fmt.Errorf("failed to get proposer: %w", err)
	}

	// Get previous block hash
	var prevHash crypto.Hash
	if d.blockHeight > 0 {
		// In practice, you'd get this from the blockchain
		prevHash = crypto.Hash{}
	}

	// Create block header
	header := types.BlockHeader{
		PrevHash:           prevHash,
		Height:             d.blockHeight + 1,
		Timestamp:          time.Now().Unix(),
		Proposer:           proposer.Address,
		TxRoot:             crypto.Hash{}, // Will be calculated
		AccountStateRoot:   crypto.Hash{}, // Will be calculated
		ValidatorStateRoot: crypto.Hash{}, // Will be calculated
		TxStateRoot:        crypto.Hash{}, // Will be calculated
	}

	// Calculate transaction root
	txRoot := d.calculateTxRoot(transactions)
	header.TxRoot = txRoot

	// Create block
	block := &types.Block{
		Header:       header,
		Transactions: transactions,
		ValidatorSig: []byte{}, // Will be signed
		Approvals:    make([][]byte, 0),
	}

	// Sign block with proposer
	blockHash := block.Hash()
	signature, err := proposerKeyPair.SignHash(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign block: %w", err)
	}

	block.ValidatorSig = append(signature.R[:], signature.S[:]...)

	return block, nil
}

// AddApproval adds an approval to a block
func (d *DPoS) AddApproval(block *types.Block, validatorKeyPair *crypto.KeyPair) error {
	// Verify validator is in committee
	validatorAddress := validatorKeyPair.GetAddress()
	isInCommittee := false
	for _, v := range d.committee {
		if v.Address == validatorAddress {
			isInCommittee = true
			break
		}
	}

	if !isInCommittee {
		return fmt.Errorf("validator not in committee: %s", validatorAddress.String())
	}

	// Sign block
	blockHash := block.Hash()
	signature, err := validatorKeyPair.SignHash(blockHash)
	if err != nil {
		return fmt.Errorf("failed to sign block: %w", err)
	}

	// Add approval
	approval := append(signature.R[:], signature.S[:]...)
	block.Approvals = append(block.Approvals, approval)

	return nil
}

// IsBlockFinalized checks if a block is finalized
func (d *DPoS) IsBlockFinalized(block *types.Block) bool {
	return len(block.Approvals) >= types.FinalityThreshold
}

// calculateTxRoot calculates the transaction root
func (d *DPoS) calculateTxRoot(transactions []types.Transaction) crypto.Hash {
	if len(transactions) == 0 {
		return crypto.Hash{}
	}

	var data []byte
	for _, tx := range transactions {
		hash := tx.Hash()
		data = append(data, hash[:]...)
	}

	return crypto.CalculateHash(data)
}

// GetEpochInfo returns information about the current epoch
func (d *DPoS) GetEpochInfo() map[string]interface{} {
	return map[string]interface{}{
		"current_epoch":    d.currentEpoch,
		"block_height":     d.blockHeight,
		"epoch_length":     types.EpochLength,
		"committee_size":   len(d.committee),
		"total_validators": len(d.validators),
		"last_epoch_time":  d.lastEpochTime,
	}
}

// GetValidatorStats returns statistics about validators
func (d *DPoS) GetValidatorStats() map[string]interface{} {
	totalStake := big.NewInt(0)
	onlineCount := 0

	for _, v := range d.validators {
		totalStake.Add(totalStake, v.GetTotalStake())
		if v.IsOnline {
			onlineCount++
		}
	}

	return map[string]interface{}{
		"total_validators":  len(d.validators),
		"online_validators": onlineCount,
		"total_stake":       totalStake.String(),
		"committee_size":    len(d.committee),
	}
}

// SimulateRandomReputation simulates random reputation for testing
func (d *DPoS) SimulateRandomReputation() {
	for _, v := range d.validators {
		// Generate random reputation between 1 and 100
		reputation := uint64(1 + 50) // Fixed value for now
		v.Reputation = reputation
	}
}
