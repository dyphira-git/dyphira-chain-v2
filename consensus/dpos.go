package consensus

import (
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"time"

	"dyphira-node/core"
	"dyphira-node/crypto"
	"dyphira-node/types"
)

// DPoS represents the DPoS consensus engine
type DPoS struct {
	validators        []*types.Validator
	committee         []*types.Validator
	currentEpoch      uint64
	blockHeight       uint64
	lastEpochTime     int64
	proposerIndex     uint64 // Current proposer index within the committee
	blocksPerProposer uint64 // Number of blocks each proposer creates (9)
	mempool           *types.Mempool
	blockchain        *core.Blockchain
}

// NewDPoS creates a new DPoS consensus engine
func NewDPoS(blockchain *core.Blockchain) *DPoS {
	return &DPoS{
		validators:        make([]*types.Validator, 0),
		committee:         make([]*types.Validator, 0),
		currentEpoch:      0,
		blockHeight:       0,
		lastEpochTime:     time.Now().Unix(),
		proposerIndex:     0,
		blocksPerProposer: types.BlocksPerEpoch,
		mempool:           types.NewMempool(10000), // 10k transaction limit
		blockchain:        blockchain,
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

// WeightedRandomSelect performs weighted random selection from a list of validators
// based on their total stake and reputation
func (d *DPoS) WeightedRandomSelect(validators []*types.Validator, count int) []*types.Validator {
	if len(validators) <= count {
		return validators
	}

	// Calculate total weight (sum of all validator weights)
	totalWeight := uint64(0)
	weights := make([]uint64, len(validators))

	for i, v := range validators {
		// Weight = total stake * reputation (convert to uint64 for simpler math)
		totalStake := v.GetTotalStake()
		// Use a reasonable conversion to avoid overflow
		stakeUint64 := uint64(0)
		if totalStake.Cmp(big.NewInt(0)) > 0 {
			// Convert big.Int to uint64, cap at max uint64 if too large
			if totalStake.BitLen() <= 64 {
				stakeUint64 = totalStake.Uint64()
			} else {
				stakeUint64 = ^uint64(0) // max uint64
			}
		}
		weight := stakeUint64 * v.Reputation
		weights[i] = weight
		totalWeight += weight
	}

	// Use block height as seed for deterministic randomness per epoch
	seed := int64(d.currentEpoch*1000000 + d.blockHeight)
	r := rand.New(rand.NewSource(seed))

	selected := make([]*types.Validator, 0, count)
	selectedIndices := make(map[int]bool)

	for len(selected) < count {
		// Generate random number between 0 and total weight
		randomWeight := r.Uint64() % totalWeight

		// Find validator corresponding to this random weight
		currentWeight := uint64(0)
		for i, weight := range weights {
			if selectedIndices[i] {
				continue // Skip already selected validators
			}

			currentWeight += weight
			if randomWeight < currentWeight {
				selected = append(selected, validators[i])
				selectedIndices[i] = true
				break
			}
		}
	}

	return selected
}

// ElectCommittee elects the committee for the current epoch using weighted random selection
func (d *DPoS) ElectCommittee() error {
	log.Printf("Starting committee election for epoch %d", d.currentEpoch)

	// Filter eligible validators
	var eligible []*types.Validator
	for _, v := range d.validators {
		if v.IsEligible() {
			eligible = append(eligible, v)
		}
	}

	log.Printf("Found %d eligible validators out of %d total validators", len(eligible), len(d.validators))

	if len(eligible) < types.CommitteeSize {
		return fmt.Errorf("insufficient eligible validators: %d < %d", len(eligible), types.CommitteeSize)
	}

	// Use weighted random selection instead of deterministic top-N
	d.committee = d.WeightedRandomSelect(eligible, types.CommitteeSize)

	log.Printf("Committee elected successfully for epoch %d using weighted random selection:", d.currentEpoch)
	for i, validator := range d.committee {
		totalStake := validator.GetTotalStake()
		weight := new(big.Int).Mul(totalStake, big.NewInt(int64(validator.Reputation)))
		log.Printf("  [%d] Validator: %s, Total Stake: %s, Reputation: %d, Weight: %s",
			i+1, validator.Address.String(), totalStake.String(), validator.Reputation, weight.String())
	}

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

	// Calculate proposer index based on block height within current epoch
	epochBlockHeight := d.blockHeight % types.EpochLength
	proposerIndex := (epochBlockHeight / d.blocksPerProposer) % uint64(len(d.committee))
	proposer := d.committee[proposerIndex]

	log.Printf("Selected proposer for block %d (epoch block %d): %s (index %d/%d)",
		d.blockHeight+1, epochBlockHeight, proposer.Address.String(), proposerIndex+1, len(d.committee))

	return proposer, nil
}

// ShouldStartNewEpoch checks if a new epoch should start
func (d *DPoS) ShouldStartNewEpoch() bool {
	return d.blockHeight%types.EpochLength == 0
}

// StartNewEpoch starts a new epoch
func (d *DPoS) StartNewEpoch() error {
	log.Printf("Starting new epoch %d at block height %d", d.currentEpoch+1, d.blockHeight)

	d.currentEpoch++
	d.lastEpochTime = time.Now().Unix()

	// Elect new committee
	err := d.ElectCommittee()
	if err != nil {
		return fmt.Errorf("failed to elect committee: %w", err)
	}

	log.Printf("New epoch %d started successfully with %d committee members", d.currentEpoch, len(d.committee))
	return nil
}

// ProcessBlock processes a block and updates consensus state
func (d *DPoS) ProcessBlock(block *types.Block) error {
	// Update block height
	d.blockHeight = block.Header.Height

	// Update proposer statistics
	proposer, err := d.GetProposer()
	if err == nil && proposer.Address == block.Header.Proposer {
		proposer.BlocksProposed++
	}

	return nil
}

// GetNextProposer returns the next proposer in the rotation
func (d *DPoS) GetNextProposer() (*types.Validator, error) {
	if len(d.committee) == 0 {
		return nil, fmt.Errorf("no committee elected")
	}

	// Calculate next proposer index
	epochBlockHeight := d.blockHeight % types.EpochLength
	nextProposerIndex := ((epochBlockHeight / d.blocksPerProposer) + 1) % uint64(len(d.committee))
	return d.committee[nextProposerIndex], nil
}

// GetCurrentProposerIndex returns the current proposer index
func (d *DPoS) GetCurrentProposerIndex() uint64 {
	if len(d.committee) == 0 {
		return 0
	}
	epochBlockHeight := d.blockHeight % types.EpochLength
	return (epochBlockHeight / d.blocksPerProposer) % uint64(len(d.committee))
}

// GetBlocksUntilNextProposer returns the number of blocks until the next proposer
func (d *DPoS) GetBlocksUntilNextProposer() uint64 {
	epochBlockHeight := d.blockHeight % types.EpochLength
	blocksInCurrentProposer := epochBlockHeight % d.blocksPerProposer
	return d.blocksPerProposer - blocksInCurrentProposer
}

// ValidateBlock validates a block from consensus perspective
func (d *DPoS) ValidateBlock(block *types.Block) error {
	if block == nil {
		return fmt.Errorf("block cannot be nil")
	}

	log.Printf("Validating block %d from consensus perspective", block.Header.Height)

	// Check if proposer is in committee
	proposer, err := d.GetProposer()
	if err != nil {
		log.Printf("Failed to get proposer for block %d: %v", block.Header.Height, err)
		return fmt.Errorf("failed to get proposer: %w", err)
	}

	if block.Header.Proposer != proposer.Address {
		log.Printf("Invalid proposer for block %d: expected %s, got %s",
			block.Header.Height, proposer.Address.String(), block.Header.Proposer.String())
		return fmt.Errorf("invalid proposer: expected %s, got %s",
			proposer.Address.String(), block.Header.Proposer.String())
	}

	log.Printf("Block %d proposer validation passed: %s", block.Header.Height, proposer.Address.String())

	// Check number of approvals
	if len(block.Approvals) < types.FinalityThreshold {
		log.Printf("Insufficient approvals for block %d: %d < %d",
			block.Header.Height, len(block.Approvals), types.FinalityThreshold)
		return fmt.Errorf("insufficient approvals: %d < %d", len(block.Approvals), types.FinalityThreshold)
	}

	// Validate approvals
	approvalCount := 0
	for i, approval := range block.Approvals {
		log.Printf("Validating approval %d/%d for block %d (signature length: %d)", i+1, len(block.Approvals), block.Header.Height, len(approval))

		// Verify approval signature
		if err := d.ValidateApproval(block, approval); err != nil {
			log.Printf("Approval %d/%d validation failed: %v", i+1, len(block.Approvals), err)
			continue // Skip invalid approvals
		}

		approvalCount++
		log.Printf("Approval %d/%d validation passed", i+1, len(block.Approvals))
	}

	if approvalCount < types.FinalityThreshold {
		log.Printf("Insufficient valid approvals for block %d: %d < %d",
			block.Header.Height, approvalCount, types.FinalityThreshold)
		return fmt.Errorf("insufficient valid approvals: %d < %d", approvalCount, types.FinalityThreshold)
	}

	log.Printf("Block %d consensus validation passed with %d approvals", block.Header.Height, approvalCount)
	return nil
}

// CreateBlock creates a new block with verified transactions from mempool
func (d *DPoS) CreateBlock(proposerKeyPair *crypto.KeyPair) (*types.Block, error) {
	log.Printf("Creating new block at height %d", d.blockHeight+1)

	// Get current proposer
	proposer, err := d.GetProposer()
	if err != nil {
		log.Printf("Failed to get proposer for block creation: %v", err)
		return nil, fmt.Errorf("failed to get proposer: %w", err)
	}

	log.Printf("Block proposer selected: %s", proposer.Address.String())

	// Get previous block hash from blockchain
	var prevHash crypto.Hash
	latestBlock, err := d.blockchain.GetLatestBlock()
	if err != nil {
		log.Printf("Failed to get latest block for prev hash: %v", err)
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}
	prevHash = latestBlock.Hash()
	log.Printf("Using previous block hash: %s", prevHash.String())

	// Get transactions from mempool
	pendingTxs := d.mempool.GetPendingTransactions(1000, types.BlockSizeLimit) // Max 1000 txs, respect block size limit
	log.Printf("Retrieved %d pending transactions from mempool", len(pendingTxs))

	// Verify each transaction before inclusion
	verifiedTxs := make([]types.Transaction, 0)
	for i, tx := range pendingTxs {
		log.Printf("Verifying transaction %d/%d: %s", i+1, len(pendingTxs), tx.Hash().String())

		err := d.ValidateTransaction(tx)
		if err != nil {
			log.Printf("Transaction %d/%d validation failed: %v", i+1, len(pendingTxs), err)
			continue // Skip invalid transactions
		}

		verifiedTxs = append(verifiedTxs, *tx)
		log.Printf("Transaction %d/%d validation passed", i+1, len(pendingTxs))
	}

	log.Printf("Verified %d/%d transactions for block inclusion", len(verifiedTxs), len(pendingTxs))

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

	// Calculate transaction root from verified transactions
	txRoot := d.calculateTxRoot(verifiedTxs)
	header.TxRoot = txRoot

	log.Printf("Block header created: Height=%d, Proposer=%s, TxRoot=%s, TxCount=%d",
		header.Height, header.Proposer.String(), txRoot.String(), len(verifiedTxs))

	// Create block
	block := &types.Block{
		Header:       header,
		Transactions: verifiedTxs,
		ValidatorSig: []byte{}, // Will be signed
		Approvals:    make([][]byte, 0),
	}

	// Sign block with proposer
	blockHash := block.Hash()
	log.Printf("Signing block %d with hash %s", block.Header.Height, blockHash.String())

	signature, err := proposerKeyPair.SignHash(blockHash)
	if err != nil {
		log.Printf("Failed to sign block %d: %v", block.Header.Height, err)
		return nil, fmt.Errorf("failed to sign block: %w", err)
	}

	block.ValidatorSig = append(signature.R[:], signature.S[:]...)
	log.Printf("Block %d signed successfully by proposer %s with %d transactions",
		block.Header.Height, proposer.Address.String(), len(verifiedTxs))

	// Remove included transactions from mempool
	d.mempool.RemoveTransactions(pendingTxs[:len(verifiedTxs)])

	return block, nil
}

// ValidateTransaction validates a transaction for inclusion in a block
func (d *DPoS) ValidateTransaction(tx *types.Transaction) error {
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}

	log.Printf("Validating transaction: Nonce=%d, To=%s, Value=%s, Type=%d",
		tx.Nonce, tx.To.String(), tx.Value.String(), tx.Type)

	// Check transaction signature
	if !tx.Verify() {
		log.Printf("Transaction signature verification failed")
		return fmt.Errorf("invalid transaction signature")
	}
	log.Printf("Transaction signature verification passed")

	// Get sender account
	sender, err := d.getSenderAddress(tx)
	if err != nil {
		log.Printf("Failed to get sender address: %v", err)
		return fmt.Errorf("failed to get sender address: %w", err)
	}
	log.Printf("Transaction sender: %s", sender.String())

	account, err := d.blockchain.GetAccount(sender)
	if err != nil {
		log.Printf("Failed to get sender account %s: %v", sender.String(), err)
		return fmt.Errorf("failed to get sender account: %w", err)
	}

	// Check nonce
	if tx.Nonce != account.Nonce {
		log.Printf("Invalid nonce: expected %d, got %d", account.Nonce, tx.Nonce)
		return fmt.Errorf("invalid nonce: expected %d, got %d", account.Nonce, tx.Nonce)
	}
	log.Printf("Transaction nonce validation passed: %d", tx.Nonce)

	// Check balance
	totalCost := new(big.Int).Add(tx.Value, tx.Fee)
	if account.Balance.Cmp(totalCost) < 0 {
		log.Printf("Insufficient balance: account has %s, transaction requires %s",
			account.Balance.String(), totalCost.String())
		return fmt.Errorf("insufficient balance")
	}
	log.Printf("Transaction balance validation passed: account balance %s >= required %s",
		account.Balance.String(), totalCost.String())

	// Check value and fee are positive
	if tx.Value.Cmp(big.NewInt(0)) < 0 {
		log.Printf("Negative transaction value: %s", tx.Value.String())
		return fmt.Errorf("negative value")
	}
	if tx.Fee.Cmp(big.NewInt(0)) < 0 {
		log.Printf("Negative transaction fee: %s", tx.Fee.String())
		return fmt.Errorf("negative fee")
	}

	log.Printf("Transaction validation completed successfully")
	return nil
}

// getSenderAddress extracts sender address from transaction signature
func (d *DPoS) getSenderAddress(tx *types.Transaction) (crypto.Address, error) {
	// Recreate transaction without signature
	txCopy := *tx
	txCopy.Signature = types.Signature{}
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

// AddTransactionToMempool adds a transaction to the mempool
func (d *DPoS) AddTransactionToMempool(tx *types.Transaction) error {
	return d.mempool.AddTransaction(tx)
}

// GetMempoolStats returns mempool statistics
func (d *DPoS) GetMempoolStats() map[string]interface{} {
	return d.mempool.GetStats()
}

// SetBlockHeight sets the current block height (for testing)
func (d *DPoS) SetBlockHeight(height uint64) {
	d.blockHeight = height
}

// ValidateApproval validates an approval signature for a block
func (d *DPoS) ValidateApproval(block *types.Block, approval []byte) error {
	if len(approval) != 64 {
		return fmt.Errorf("invalid approval signature length: %d", len(approval))
	}

	// Extract signature components
	var r, s [32]byte
	copy(r[:], approval[:32])
	copy(s[:], approval[32:])

	// Create signature object
	signature := &crypto.Signature{
		R: r,
		S: s,
		V: 27, // Assume v=27 for now
	}

	// Calculate block hash
	blockHash := block.Hash()

	// Try to recover public key from signature
	pubKey, err := crypto.Ecrecover(blockHash[:], approval, 27)
	if err != nil {
		// Try with v=28
		pubKey, err = crypto.Ecrecover(blockHash[:], approval, 28)
		if err != nil {
			return fmt.Errorf("failed to recover public key from approval: %w", err)
		}
		signature.V = 28
	}

	// Derive validator address from public key
	validatorAddress := crypto.PubToAddress(pubKey)

	// Verify validator is in committee
	isInCommittee := false
	for _, v := range d.committee {
		if v.Address == validatorAddress {
			isInCommittee = true
			break
		}
	}

	if !isInCommittee {
		return fmt.Errorf("approval from validator not in committee: %s", validatorAddress.String())
	}

	// Verify signature cryptographically
	if !crypto.VerifySignature(blockHash, signature, pubKey) {
		return fmt.Errorf("invalid approval signature from validator: %s", validatorAddress.String())
	}

	log.Printf("Approval validation passed for validator: %s", validatorAddress.String())
	return nil
}

// AddApproval adds an approval to a block
func (d *DPoS) AddApproval(block *types.Block, validatorKeyPair *crypto.KeyPair) error {
	validatorAddress := validatorKeyPair.GetAddress()
	log.Printf("Processing approval for block %d from validator %s", block.Header.Height, validatorAddress.String())

	// Verify validator is in committee
	var validator *types.Validator
	isInCommittee := false
	for _, v := range d.committee {
		if v.Address == validatorAddress {
			validator = v
			isInCommittee = true
			break
		}
	}

	if !isInCommittee {
		log.Printf("Validator %s not in committee, approval rejected", validatorAddress.String())
		return fmt.Errorf("validator not in committee: %s", validatorAddress.String())
	}

	log.Printf("Validator %s is in committee, processing approval", validatorAddress.String())

	// Check if validator already approved this block
	blockHash := block.Hash()
	for _, existingApproval := range block.Approvals {
		// Try to recover validator from existing approval
		if existingPubKey, err := crypto.Ecrecover(blockHash[:], existingApproval, 27); err == nil {
			existingValidator := crypto.PubToAddress(existingPubKey)
			if existingValidator == validatorAddress {
				log.Printf("Validator %s already approved block %d", validatorAddress.String(), block.Header.Height)
				return fmt.Errorf("duplicate approval from validator: %s", validatorAddress.String())
			}
		}
		// Try with v=28
		if existingPubKey, err := crypto.Ecrecover(blockHash[:], existingApproval, 28); err == nil {
			existingValidator := crypto.PubToAddress(existingPubKey)
			if existingValidator == validatorAddress {
				log.Printf("Validator %s already approved block %d", validatorAddress.String(), block.Header.Height)
				return fmt.Errorf("duplicate approval from validator: %s", validatorAddress.String())
			}
		}
	}

	// Sign block
	log.Printf("Validator %s signing block %d with hash %s", validatorAddress.String(), block.Header.Height, blockHash.String())

	signature, err := validatorKeyPair.SignHash(blockHash)
	if err != nil {
		log.Printf("Failed to sign block %d with validator %s: %v", block.Header.Height, validatorAddress.String(), err)
		return fmt.Errorf("failed to sign block: %w", err)
	}

	// Add approval
	approval := append(signature.R[:], signature.S[:]...)
	block.Approvals = append(block.Approvals, approval)

	// Update validator statistics
	validator.BlocksApproved++

	log.Printf("Approval added for block %d by validator %s. Total approvals: %d/%d",
		block.Header.Height, validatorAddress.String(), len(block.Approvals), len(d.committee))

	return nil
}

// GetApprovalCount returns the number of approvals for a block
func (d *DPoS) GetApprovalCount(block *types.Block) int {
	return len(block.Approvals)
}

// GetCommitteeApprovalPercentage returns the percentage of committee members who approved
func (d *DPoS) GetCommitteeApprovalPercentage(block *types.Block) float64 {
	if len(d.committee) == 0 {
		return 0.0
	}
	return float64(len(block.Approvals)) / float64(len(d.committee)) * 100.0
}

// IsBlockFinalized checks if a block is finalized
func (d *DPoS) IsBlockFinalized(block *types.Block) bool {
	approvalCount := len(block.Approvals)
	requiredApprovals := (len(d.committee) * 2) / 3 // 2/3 majority
	return approvalCount >= requiredApprovals
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

// LogConsensusState logs the current consensus state for debugging
func (d *DPoS) LogConsensusState() {
	log.Printf("=== Consensus State ===")
	log.Printf("Current Epoch: %d", d.currentEpoch)
	log.Printf("Block Height: %d", d.blockHeight)
	log.Printf("Total Validators: %d", len(d.validators))
	log.Printf("Committee Size: %d", len(d.committee))

	// Log committee members
	if len(d.committee) > 0 {
		log.Printf("Committee Members:")
		for i, validator := range d.committee {
			log.Printf("  [%d] %s - Stake: %s, Reputation: %d, Blocks Proposed: %d, Blocks Approved: %d",
				i+1, validator.Address.String(), validator.GetTotalStake().String(),
				validator.Reputation, validator.BlocksProposed, validator.BlocksApproved)
		}

		// Get current proposer
		if proposer, err := d.GetProposer(); err == nil {
			log.Printf("Current Proposer: %s", proposer.Address.String())
		}

		// Get next proposer
		if nextProposer, err := d.GetNextProposer(); err == nil {
			log.Printf("Next Proposer: %s", nextProposer.Address.String())
		}

		// Calculate blocks until next proposer
		blocksUntilNext := d.GetBlocksUntilNextProposer()
		log.Printf("Blocks until next proposer: %d", blocksUntilNext)
	} else {
		log.Printf("No committee elected")
	}

	// Log validator statistics
	onlineCount := 0
	totalStake := big.NewInt(0)
	for _, v := range d.validators {
		if v.IsOnline {
			onlineCount++
		}
		totalStake.Add(totalStake, v.GetTotalStake())
	}

	log.Printf("Validator Statistics:")
	log.Printf("  Online Validators: %d/%d", onlineCount, len(d.validators))
	log.Printf("  Total Stake: %s", totalStake.String())

	// Check if new epoch should start
	if d.ShouldStartNewEpoch() {
		log.Printf("*** New epoch should start at next block ***")
	}

	log.Printf("======================")
}

// GetCurrentEpoch returns the current epoch
func (d *DPoS) GetCurrentEpoch() uint64 {
	return d.currentEpoch
}

// GetBlockHeight returns the current block height
func (d *DPoS) GetBlockHeight() uint64 {
	return d.blockHeight
}
