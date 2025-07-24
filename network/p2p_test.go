package network

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"dyphira-node/crypto"
	"dyphira-node/state"
	"dyphira-node/types"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockBlockchainInterface is a mock implementation of BlockchainInterface
type MockBlockchainInterface struct {
	mock.Mock
}

func (m *MockBlockchainInterface) GetLatestHeight() uint64 {
	args := m.Called()
	return args.Get(0).(uint64)
}

func (m *MockBlockchainInterface) GetBlockByHeight(height uint64) (*types.Block, error) {
	args := m.Called(height)
	return args.Get(0).(*types.Block), args.Error(1)
}

func (m *MockBlockchainInterface) GetBlockByHash(hash crypto.Hash) (*types.Block, error) {
	args := m.Called(hash)
	return args.Get(0).(*types.Block), args.Error(1)
}

func (m *MockBlockchainInterface) AddBlock(block *types.Block) error {
	args := m.Called(block)
	return args.Error(0)
}

func (m *MockBlockchainInterface) GetAccount(address crypto.Address) (*state.Account, error) {
	args := m.Called(address)
	return args.Get(0).(*state.Account), args.Error(1)
}

func (m *MockBlockchainInterface) GetAllValidators() ([]*state.Validator, error) {
	args := m.Called()
	return args.Get(0).([]*state.Validator), args.Error(1)
}

// MockConsensusInterface is a mock implementation of ConsensusInterface
type MockConsensusInterface struct {
	mock.Mock
}

func (m *MockConsensusInterface) GetCommittee() []*types.Validator {
	args := m.Called()
	return args.Get(0).([]*types.Validator)
}

func (m *MockConsensusInterface) GetEpochInfo() map[string]interface{} {
	args := m.Called()
	return args.Get(0).(map[string]interface{})
}

func (m *MockConsensusInterface) AddValidator(validator *types.Validator) error {
	args := m.Called(validator)
	return args.Error(0)
}

func (m *MockConsensusInterface) AddTransactionToMempool(tx *types.Transaction) error {
	args := m.Called(tx)
	return args.Error(0)
}

func TestNewP2PNode(t *testing.T) {
	// Create mock interfaces
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	// Create P2P node
	node, err := NewP2PNode(8080, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	assert.NotNil(t, node)
	assert.NotNil(t, node.host)
	assert.NotNil(t, node.pubsub)
	assert.NotNil(t, node.topics)
	assert.NotNil(t, node.subs)
	assert.NotNil(t, node.peers)
	assert.NotNil(t, node.handlers)
	assert.Equal(t, mockBlockchain, node.blockchain)
	assert.Equal(t, mockConsensus, node.consensus)

	// Clean up
	err = node.Stop()
	assert.NoError(t, err)
}

func TestP2PNodeStartStop(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8081, mockBlockchain, mockConsensus)
	assert.NoError(t, err)

	// Start node
	err = node.Start()
	assert.NoError(t, err)

	// Stop node
	err = node.Stop()
	assert.NoError(t, err)
}

func TestJoinTopic(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8082, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start node
	err = node.Start()
	assert.NoError(t, err)

	// Join topic
	err = node.JoinTopic("test-topic")
	assert.NoError(t, err)

	// Verify topic was joined
	assert.Contains(t, node.topics, "test-topic")
	assert.Contains(t, node.subs, "test-topic")
}

func TestPublishBlock(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8083, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start node
	err = node.Start()
	assert.NoError(t, err)

	// Join block topic
	err = node.JoinTopic("blocks")
	assert.NoError(t, err)

	// Create a test block
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	// Publish block
	err = node.PublishBlock(block)
	assert.NoError(t, err)
}

func TestPublishTransaction(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8084, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start node
	err = node.Start()
	assert.NoError(t, err)

	// Join transaction topic
	err = node.JoinTopic("transactions")
	assert.NoError(t, err)

	// Create a test transaction
	tx := &types.Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Timestamp: time.Now().Unix(),
		Type:      types.TxTypeTransfer,
		Data:      []byte{},
	}

	// Publish transaction
	err = node.PublishTransaction(tx)
	assert.NoError(t, err)
}

func TestPublishApproval(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8085, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start node and join topic
	err = node.Start()
	assert.NoError(t, err)

	err = node.JoinTopic("approvals")
	assert.NoError(t, err)

	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	approval := &types.ConsensusMsg{
		Height:    1,
		Sender:    keyPair.GetAddress(),
		Type:      types.MsgTypeApproval,
		Signature: []byte{},
	}

	// Publish approval
	err = node.PublishApproval(approval)
	assert.NoError(t, err)
}

func TestHandleBlockMessage(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8086, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Create a test block
	block := &types.Block{
		Header: types.BlockHeader{
			Height:    1,
			Timestamp: time.Now().Unix(),
			Proposer:  crypto.Address{},
		},
		Transactions: []types.Transaction{},
		ValidatorSig: []byte{},
		Approvals:    [][]byte{},
	}

	// Set up mock expectations
	mockBlockchain.On("GetLatestHeight").Return(uint64(0))
	mockBlockchain.On("AddBlock", block).Return(nil)

	// Create block message
	blockData, err := json.Marshal(block)
	assert.NoError(t, err)

	msg := &Message{
		Type:      "block",
		Data:      blockData,
		Timestamp: time.Now().Unix(),
		Sender:    "test-peer",
		Height:    1,
	}

	// Handle block message
	err = node.handleBlockMessage(msg)
	assert.NoError(t, err)

	// Verify mock was called
	mockBlockchain.AssertExpectations(t)
}

func TestHandleTransactionMessage(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8087, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Create a key pair for signing
	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	// Create a test transaction
	tx := &types.Transaction{
		Nonce:     1,
		To:        crypto.Address{},
		Value:     big.NewInt(1000),
		Fee:       big.NewInt(10),
		Timestamp: time.Now().Unix(),
		Type:      types.TxTypeTransfer,
		Data:      []byte{},
	}

	// Sign the transaction
	err = tx.Sign(keyPair)
	assert.NoError(t, err)

	// Set up mock expectations
	mockConsensus.On("AddTransactionToMempool", tx).Return(nil)

	// Create transaction message
	txData, err := json.Marshal(tx)
	assert.NoError(t, err)

	msg := &Message{
		Type:      "transaction",
		Data:      txData,
		Timestamp: time.Now().Unix(),
		Sender:    "test-peer",
		Height:    1,
	}

	// Handle transaction message
	err = node.handleTransactionMessage(msg)
	assert.NoError(t, err)

	// Verify mock was called
	mockConsensus.AssertExpectations(t)
}

func TestHandleApprovalMessage(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8088, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	keyPair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	approval := &types.ConsensusMsg{
		Height:    1,
		Sender:    keyPair.GetAddress(),
		Type:      types.MsgTypeApproval,
		Signature: []byte{},
	}

	// Set up mock expectations
	mockBlockchain.On("GetLatestHeight").Return(uint64(0))

	// Create approval message
	approvalData, err := json.Marshal(approval)
	assert.NoError(t, err)

	msg := &Message{
		Type:      "approval",
		Data:      approvalData,
		Timestamp: time.Now().Unix(),
		Sender:    "test-peer",
		Height:    1,
	}

	// Handle approval message
	err = node.handleApprovalMessage(msg)
	assert.NoError(t, err)

	// Verify mock was called
	mockBlockchain.AssertExpectations(t)
}

func TestHandleStateSyncRequest(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8089, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start the node and join the state sync topic
	err = node.Start()
	assert.NoError(t, err)
	err = node.JoinTopic("state_sync")
	assert.NoError(t, err)

	// Create a proper peer.ID
	peerID, err := peer.Decode("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE1DW3p9Gk")
	assert.NoError(t, err)

	// Create a test state sync request
	request := &StateSyncRequest{
		FromHeight: 0,
		ToHeight:   2, // Reduced range to avoid too many mock expectations
		Requester:  peerID,
	}

	// Set up mock expectations for the heights that will be called
	for height := uint64(0); height <= 2; height++ {
		mockBlockchain.On("GetBlockByHeight", height).Return(&types.Block{}, nil)
	}

	// Create state sync request message
	requestData, err := json.Marshal(request)
	assert.NoError(t, err)

	msg := &Message{
		Type:      "state_sync_request",
		Data:      requestData,
		Timestamp: time.Now().Unix(),
		Sender:    peerID.String(),
		Height:    1,
	}

	// Handle state sync request message
	err = node.handleStateSyncRequest(msg)
	assert.NoError(t, err)

	// Verify mock was called
	mockBlockchain.AssertExpectations(t)
}

func TestHandleStateSyncResponse(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8090, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Create a test state sync response
	response := &StateSyncResponse{
		Blocks:     []*types.Block{},
		Accounts:   []*AccountInfo{},
		Validators: []*state.Validator{},
		Error:      "",
	}

	// Create state sync response message
	responseData, err := json.Marshal(response)
	assert.NoError(t, err)

	msg := &Message{
		Type:      "state_sync_response",
		Data:      responseData,
		Timestamp: time.Now().Unix(),
		Sender:    "test-peer",
		Height:    1,
	}

	// Handle state sync response message
	err = node.handleStateSyncResponse(msg)
	assert.NoError(t, err)
}

func TestHandleNewNodeRequest(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8091, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start the node and join the new node topic
	err = node.Start()
	assert.NoError(t, err)
	err = node.JoinTopic("new_node")
	assert.NoError(t, err)

	// Create a proper peer.ID
	peerID, err := peer.Decode("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE1DW3p9Gk")
	assert.NoError(t, err)

	// Create a test new node request
	request := &NewNodeRequest{
		NodeID:  peerID,
		Address: "127.0.0.1:8080",
	}

	// Set up mock expectations
	mockBlockchain.On("GetBlockByHeight", uint64(0)).Return(&types.Block{}, nil)

	// Create new node request message
	requestData, err := json.Marshal(request)
	assert.NoError(t, err)

	msg := &Message{
		Type:      "new_node_request",
		Data:      requestData,
		Timestamp: time.Now().Unix(),
		Sender:    peerID.String(),
		Height:    1,
	}

	// Handle new node request message
	err = node.handleNewNodeRequest(msg)
	assert.NoError(t, err)

	// Verify mock was called
	mockBlockchain.AssertExpectations(t)
}

func TestHandleNewNodeResponse(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8092, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Create a test new node response
	response := &NewNodeResponse{
		Success:      true,
		Peers:        []string{"127.0.0.1:8080"},
		GenesisBlock: &types.Block{},
		Error:        "",
	}

	// Create new node response message
	responseData, err := json.Marshal(response)
	assert.NoError(t, err)

	msg := &Message{
		Type:      "new_node_response",
		Data:      responseData,
		Timestamp: time.Now().Unix(),
		Sender:    "test-peer",
		Height:    1,
	}

	// Handle new node response message
	err = node.handleNewNodeResponse(msg)
	assert.NoError(t, err)
}

func TestHandlePeerDiscovery(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8093, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Create a test peer discovery message
	msg := &Message{
		Type:      "peer_discovery",
		Data:      []byte(`{"peers": ["127.0.0.1:8080"]}`),
		Timestamp: time.Now().Unix(),
		Sender:    "test-peer",
		Height:    1,
	}

	// Handle peer discovery message
	err = node.handlePeerDiscovery(msg)
	assert.NoError(t, err)
}

func TestRequestStateSync(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8094, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start node
	err = node.Start()
	assert.NoError(t, err)

	// Join state sync topic
	err = node.JoinTopic("state_sync")
	assert.NoError(t, err)

	// Request state sync
	err = node.RequestStateSync(0, 10)
	assert.NoError(t, err)
}

func TestRequestJoinNetwork(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8095, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start node
	err = node.Start()
	assert.NoError(t, err)

	// Join new node topic
	err = node.JoinTopic("new_node")
	assert.NoError(t, err)

	// Request to join network
	err = node.RequestJoinNetwork()
	assert.NoError(t, err)
}

func TestConnectToPeer(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8096, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start node
	err = node.Start()
	assert.NoError(t, err)

	// Try to connect to a peer (this will fail since there's no peer at that address)
	err = node.ConnectToPeer("/ip4/127.0.0.1/tcp/9999/p2p/QmInvalidPeerID")
	assert.Error(t, err) // Expected to fail with invalid peer ID
}

func TestGetPeers(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8097, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Get peers
	peers := node.GetPeers()
	assert.NotNil(t, peers)
	assert.IsType(t, []*PeerInfo{}, peers)
}

func TestGetAddress(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8098, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	address := node.GetAddress()
	assert.NotEmpty(t, address)
	assert.Contains(t, address, "/p2p/")
}

func TestPublishStateSyncResponse(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8099, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start node
	err = node.Start()
	assert.NoError(t, err)

	// Join state sync topic
	err = node.JoinTopic("state_sync")
	assert.NoError(t, err)

	// Create a test state sync response
	response := &StateSyncResponse{
		Blocks:     []*types.Block{},
		Accounts:   []*AccountInfo{},
		Validators: []*state.Validator{},
		Error:      "",
	}

	// Create a mock peer ID
	targetPeer := peer.ID("test-peer")

	// Publish state sync response
	err = node.PublishStateSyncResponse(response, targetPeer)
	assert.NoError(t, err)
}

func TestPublishNewNodeResponse(t *testing.T) {
	mockBlockchain := &MockBlockchainInterface{}
	mockConsensus := &MockConsensusInterface{}

	node, err := NewP2PNode(8100, mockBlockchain, mockConsensus)
	assert.NoError(t, err)
	defer node.Stop()

	// Start node
	err = node.Start()
	assert.NoError(t, err)

	// Join new node topic
	err = node.JoinTopic("new_node")
	assert.NoError(t, err)

	// Create a test new node response
	response := &NewNodeResponse{
		Success:      true,
		Peers:        []string{"127.0.0.1:8080"},
		GenesisBlock: &types.Block{},
		Error:        "",
	}

	// Create a mock peer ID
	targetPeer := peer.ID("test-peer")

	// Publish new node response
	err = node.PublishNewNodeResponse(response, targetPeer)
	assert.NoError(t, err)
}

func TestMessageStruct(t *testing.T) {
	// Test Message struct creation and JSON marshaling
	msg := &Message{
		Type:      "test",
		Data:      []byte(`{"key": "value"}`),
		Timestamp: time.Now().Unix(),
		Sender:    "test-sender",
		Height:    1,
	}

	// Marshal to JSON
	data, err := json.Marshal(msg)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal from JSON
	var unmarshaledMsg Message
	err = json.Unmarshal(data, &unmarshaledMsg)
	assert.NoError(t, err)
	assert.Equal(t, msg.Type, unmarshaledMsg.Type)
	assert.Equal(t, msg.Sender, unmarshaledMsg.Sender)
	assert.Equal(t, msg.Height, unmarshaledMsg.Height)
}

func TestStateSyncRequestStruct(t *testing.T) {
	// Test StateSyncRequest struct creation and JSON marshaling
	// Create a proper peer.ID
	peerID, err := peer.Decode("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE1DW3p9Gk")
	assert.NoError(t, err)

	request := &StateSyncRequest{
		FromHeight: 0,
		ToHeight:   10,
		Requester:  peerID,
	}

	// Marshal to JSON
	data, err := json.Marshal(request)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal from JSON
	var unmarshaledRequest StateSyncRequest
	err = json.Unmarshal(data, &unmarshaledRequest)
	assert.NoError(t, err)
	assert.Equal(t, request.FromHeight, unmarshaledRequest.FromHeight)
	assert.Equal(t, request.ToHeight, unmarshaledRequest.ToHeight)
	assert.Equal(t, request.Requester.String(), unmarshaledRequest.Requester.String())
}

func TestStateSyncResponseStruct(t *testing.T) {
	// Test StateSyncResponse struct creation and JSON marshaling
	response := &StateSyncResponse{
		Blocks:     []*types.Block{},
		Accounts:   []*AccountInfo{},
		Validators: []*state.Validator{},
		Error:      "",
	}

	// Marshal to JSON
	data, err := json.Marshal(response)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal from JSON
	var unmarshaledResponse StateSyncResponse
	err = json.Unmarshal(data, &unmarshaledResponse)
	assert.NoError(t, err)
	assert.Equal(t, response.Error, unmarshaledResponse.Error)
}

func TestNewNodeRequestStruct(t *testing.T) {
	// Test NewNodeRequest struct creation and JSON marshaling
	// Create a proper peer.ID
	peerID, err := peer.Decode("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE1DW3p9Gk")
	assert.NoError(t, err)

	request := &NewNodeRequest{
		NodeID:  peerID,
		Address: "127.0.0.1:8080",
	}

	// Marshal to JSON
	data, err := json.Marshal(request)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal from JSON
	var unmarshaledRequest NewNodeRequest
	err = json.Unmarshal(data, &unmarshaledRequest)
	assert.NoError(t, err)
	assert.Equal(t, request.NodeID.String(), unmarshaledRequest.NodeID.String())
	assert.Equal(t, request.Address, unmarshaledRequest.Address)
}

func TestNewNodeResponseStruct(t *testing.T) {
	// Test NewNodeResponse struct creation and JSON marshaling
	response := &NewNodeResponse{
		Success:      true,
		Peers:        []string{"127.0.0.1:8080"},
		GenesisBlock: &types.Block{},
		Error:        "",
	}

	// Marshal to JSON
	data, err := json.Marshal(response)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal from JSON
	var unmarshaledResponse NewNodeResponse
	err = json.Unmarshal(data, &unmarshaledResponse)
	assert.NoError(t, err)
	assert.Equal(t, response.Success, unmarshaledResponse.Success)
	assert.Equal(t, response.Error, unmarshaledResponse.Error)
}

func TestPeerInfoStruct(t *testing.T) {
	// Create a proper peer.ID
	peerID, err := peer.Decode("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE1DW3p9Gk")
	assert.NoError(t, err)

	peerInfo := &PeerInfo{
		ID:        peerID,
		Addresses: nil,
		Protocols: []string{},
		LastSeen:  time.Now(),
		IsNew:     true,
	}

	assert.NotNil(t, peerInfo)
	assert.Equal(t, peerID.String(), peerInfo.ID.String())
	assert.True(t, peerInfo.IsNew)
}

func TestRandomSource(t *testing.T) {
	// Test RandomSource struct
	rs := RandomSource{}

	// Test Read method
	buffer := make([]byte, 10)
	n, err := rs.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, 10, n)
	assert.NotEqual(t, make([]byte, 10), buffer) // Should be filled with random data
}
