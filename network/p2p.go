package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"dyphira-node/crypto"
	"dyphira-node/state"
	"dyphira-node/types"

	"math/rand"

	"github.com/libp2p/go-libp2p"
	ps "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/multiformats/go-multiaddr"
)

// P2PNode represents a P2P network node
type P2PNode struct {
	host       host.Host
	pubsub     *ps.PubSub
	topics     map[string]*ps.Topic
	subs       map[string]*ps.Subscription
	peers      map[peer.ID]*PeerInfo
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	blockchain BlockchainInterface
	consensus  ConsensusInterface
	handlers   map[string]MessageHandler
}

// BlockchainInterface defines the interface for blockchain operations
type BlockchainInterface interface {
	GetLatestHeight() uint64
	GetBlockByHeight(height uint64) (*types.Block, error)
	GetBlockByHash(hash crypto.Hash) (*types.Block, error)
	AddBlock(block *types.Block) error
	GetAccount(address crypto.Address) (*state.Account, error)
	GetAllValidators() ([]*state.Validator, error)
}

// ConsensusInterface defines the interface for consensus operations
type ConsensusInterface interface {
	GetCommittee() []*types.Validator
	GetEpochInfo() map[string]interface{}
	AddValidator(validator *types.Validator) error
}

// MessageHandler is a function that handles specific message types
type MessageHandler func(*Message) error

// StateSyncRequest represents a state synchronization request
type StateSyncRequest struct {
	FromHeight uint64  `json:"from_height"`
	ToHeight   uint64  `json:"to_height"`
	Requester  peer.ID `json:"requester"`
}

// StateSyncResponse represents a state synchronization response
type StateSyncResponse struct {
	Blocks     []*types.Block     `json:"blocks"`
	Accounts   []*AccountInfo     `json:"accounts"`
	Validators []*state.Validator `json:"validators"`
	Error      string             `json:"error,omitempty"`
}

// AccountInfo represents account information for state sync
type AccountInfo struct {
	Address crypto.Address `json:"address"`
	Account *state.Account `json:"account"`
}

// NewNodeRequest represents a new node joining the network
type NewNodeRequest struct {
	NodeID  peer.ID `json:"node_id"`
	Address string  `json:"address"`
}

// NewNodeResponse represents a response to a new node request
type NewNodeResponse struct {
	Success      bool         `json:"success"`
	Peers        []string     `json:"peers"`
	GenesisBlock *types.Block `json:"genesis_block,omitempty"`
	Error        string       `json:"error,omitempty"`
}

// PeerInfo represents information about a peer
type PeerInfo struct {
	ID        peer.ID
	Addresses []multiaddr.Multiaddr
	Protocols []string
	LastSeen  time.Time
	IsNew     bool // Flag to track if this is a new node
}

// Message represents a network message
type Message struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp int64           `json:"timestamp"`
	Sender    string          `json:"sender"`
	Height    uint64          `json:"height,omitempty"`
}

// NewP2PNode creates a new P2P node
func NewP2PNode(port int, blockchain BlockchainInterface, consensus ConsensusInterface) (*P2PNode, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create libp2p host
	host, err := libp2p.New(
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)),
		libp2p.Security(noise.ID, noise.New),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Create pubsub
	pubsub, err := ps.NewGossipSub(ctx, host)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create pubsub: %w", err)
	}

	node := &P2PNode{
		host:       host,
		pubsub:     pubsub,
		topics:     make(map[string]*ps.Topic),
		subs:       make(map[string]*ps.Subscription),
		peers:      make(map[peer.ID]*PeerInfo),
		ctx:        ctx,
		cancel:     cancel,
		blockchain: blockchain,
		consensus:  consensus,
		handlers:   make(map[string]MessageHandler),
	}

	// Set up network event handlers
	host.Network().Notify(&network.NotifyBundle{
		ConnectedF:    node.onPeerConnected,
		DisconnectedF: node.onPeerDisconnected,
	})

	// Register message handlers
	node.registerHandlers()

	return node, nil
}

// registerHandlers registers message handlers for different message types
func (n *P2PNode) registerHandlers() {
	n.handlers["block"] = n.handleBlockMessage
	n.handlers["transaction"] = n.handleTransactionMessage
	n.handlers["approval"] = n.handleApprovalMessage
	n.handlers["state_sync_request"] = n.handleStateSyncRequest
	n.handlers["state_sync_response"] = n.handleStateSyncResponse
	n.handlers["new_node_request"] = n.handleNewNodeRequest
	n.handlers["new_node_response"] = n.handleNewNodeResponse
	n.handlers["peer_discovery"] = n.handlePeerDiscovery
}

// Start starts the P2P node
func (n *P2PNode) Start() error {
	// Join topics
	topics := []string{
		"/dyphira/blocks",
		"/dyphira/txs",
		"/dyphira/approvals",
		"/dyphira/state_sync",
		"/dyphira/node_management",
	}

	for _, topicName := range topics {
		err := n.JoinTopic(topicName)
		if err != nil {
			return fmt.Errorf("failed to join topic %s: %w", topicName, err)
		}
	}

	// Start background workers
	go n.peerDiscoveryWorker()

	log.Printf("P2P node started on %s", n.host.Addrs()[0])
	return nil
}

// Stop stops the P2P node
func (n *P2PNode) Stop() error {
	// Cancel context to stop all goroutines
	n.cancel()

	// Close all subscriptions
	n.mu.Lock()
	for _, sub := range n.subs {
		if sub != nil {
			sub.Cancel()
		}
	}
	n.mu.Unlock()

	// Close all topics
	n.mu.Lock()
	for _, topic := range n.topics {
		if topic != nil {
			topic.Close()
		}
	}
	n.mu.Unlock()

	// Close the libp2p host
	return n.host.Close()
}

// JoinTopic joins a pubsub topic
func (n *P2PNode) JoinTopic(topicName string) error {
	topic, err := n.pubsub.Join(topicName)
	if err != nil {
		return fmt.Errorf("failed to join topic: %w", err)
	}

	sub, err := topic.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe to topic: %w", err)
	}

	n.topics[topicName] = topic
	n.subs[topicName] = sub

	// Start message handler
	go n.handleMessages(topicName, sub)

	return nil
}

// handleMessages handles incoming messages
func (n *P2PNode) handleMessages(topicName string, sub *ps.Subscription) {
	for {
		msg, err := sub.Next(n.ctx)
		if err != nil {
			if n.ctx.Err() != nil {
				return // Context cancelled
			}
			log.Printf("Error reading message: %v", err)
			continue
		}

		// Skip our own messages
		if msg.ReceivedFrom == n.host.ID() {
			continue
		}

		// Parse message
		var networkMsg Message
		err = json.Unmarshal(msg.Data, &networkMsg)
		if err != nil {
			log.Printf("Error unmarshaling message: %v", err)
			continue
		}

		// Handle message based on type
		if handler, exists := n.handlers[networkMsg.Type]; exists {
			err = handler(&networkMsg)
			if err != nil {
				log.Printf("Error handling message %s: %v", networkMsg.Type, err)
			}
		} else {
			log.Printf("Unknown message type: %s", networkMsg.Type)
		}
	}
}

// handleBlockMessage handles block messages
func (n *P2PNode) handleBlockMessage(msg *Message) error {
	var block types.Block
	err := json.Unmarshal(msg.Data, &block)
	if err != nil {
		return fmt.Errorf("error unmarshaling block: %w", err)
	}

	log.Printf("Received block %d from %s", block.Header.Height, msg.Sender)

	// Check if we already have this block
	currentHeight := n.blockchain.GetLatestHeight()
	if block.Header.Height <= currentHeight {
		// We already have this block or a higher one, skip
		log.Printf("Skipping block %d (current height: %d)", block.Header.Height, currentHeight)
		return nil
	}

	// Only try to add the block if it's the next expected block
	if block.Header.Height == currentHeight+1 {
		err = n.blockchain.AddBlock(&block)
		if err != nil {
			log.Printf("Failed to add block %d: %v", block.Header.Height, err)
			return nil // Don't return error, just log it
		}
		log.Printf("Successfully added block %d", block.Header.Height)
	} else {
		log.Printf("Received block %d but expected %d, skipping", block.Header.Height, currentHeight+1)
	}

	return nil
}

// handleTransactionMessage handles transaction messages
func (n *P2PNode) handleTransactionMessage(msg *Message) error {
	var tx types.Transaction
	err := json.Unmarshal(msg.Data, &tx)
	if err != nil {
		return fmt.Errorf("error unmarshaling transaction: %w", err)
	}

	log.Printf("Received transaction from %s", msg.Sender)
	// In practice, you'd add this to the mempool
	return nil
}

// handleApprovalMessage handles approval messages
func (n *P2PNode) handleApprovalMessage(msg *Message) error {
	var approval types.ConsensusMsg
	err := json.Unmarshal(msg.Data, &approval)
	if err != nil {
		return fmt.Errorf("error unmarshaling approval: %w", err)
	}

	log.Printf("Received approval for block %d from %s", approval.Height, msg.Sender)
	// In practice, you'd forward this to the consensus engine
	return nil
}

// handleStateSyncRequest handles state synchronization requests
func (n *P2PNode) handleStateSyncRequest(msg *Message) error {
	var request StateSyncRequest
	err := json.Unmarshal(msg.Data, &request)
	if err != nil {
		return fmt.Errorf("error unmarshaling state sync request: %w", err)
	}

	log.Printf("Received state sync request from %s: blocks %d-%d",
		request.Requester, request.FromHeight, request.ToHeight)

	// Create response
	response := &StateSyncResponse{}

	// Get blocks in the requested range
	var blocks []*types.Block
	for height := request.FromHeight; height <= request.ToHeight; height++ {
		block, err := n.blockchain.GetBlockByHeight(height)
		if err != nil {
			response.Error = fmt.Sprintf("failed to get block %d: %v", height, err)
			break
		}
		blocks = append(blocks, block)
	}

	if response.Error == "" {
		response.Blocks = blocks
		log.Printf("State sync: sending %d blocks to %s", len(blocks), request.Requester)
	}

	// Publish response directly
	return n.PublishStateSyncResponse(response, request.Requester)
}

// handleStateSyncResponse handles state synchronization responses
func (n *P2PNode) handleStateSyncResponse(msg *Message) error {
	var response StateSyncResponse
	err := json.Unmarshal(msg.Data, &response)
	if err != nil {
		return fmt.Errorf("error unmarshaling state sync response: %w", err)
	}

	log.Printf("Received state sync response with %d blocks", len(response.Blocks))

	// Process received blocks
	for _, block := range response.Blocks {
		err = n.blockchain.AddBlock(block)
		if err != nil {
			log.Printf("Failed to add block %d: %v", block.Header.Height, err)
		}
	}

	return nil
}

// handleNewNodeRequest handles new node requests
func (n *P2PNode) handleNewNodeRequest(msg *Message) error {
	var request NewNodeRequest
	err := json.Unmarshal(msg.Data, &request)
	if err != nil {
		return fmt.Errorf("error unmarshaling new node request: %w", err)
	}

	log.Printf("Received new node request from %s", request.NodeID)

	// Create response
	response := &NewNodeResponse{Success: true}

	// Get list of peers
	n.mu.RLock()
	peers := make([]string, 0, len(n.peers))
	for _, peer := range n.peers {
		if len(peer.Addresses) > 0 {
			addr := fmt.Sprintf("%s/p2p/%s", peer.Addresses[0], peer.ID)
			peers = append(peers, addr)
		}
	}
	n.mu.RUnlock()

	response.Peers = peers

	// Get genesis block if requested
	genesis, err := n.blockchain.GetBlockByHeight(0)
	if err == nil {
		response.GenesisBlock = genesis
	}

	log.Printf("New node response: sending %d peers to %s", len(peers), request.NodeID)

	// Publish response directly
	return n.PublishNewNodeResponse(response, request.NodeID)
}

// handleNewNodeResponse handles new node responses
func (n *P2PNode) handleNewNodeResponse(msg *Message) error {
	var response NewNodeResponse
	err := json.Unmarshal(msg.Data, &response)
	if err != nil {
		return fmt.Errorf("error unmarshaling new node response: %w", err)
	}

	log.Printf("Received new node response: success=%v, peers=%d",
		response.Success, len(response.Peers))

	// Connect to provided peers
	for _, peerAddr := range response.Peers {
		err = n.ConnectToPeer(peerAddr)
		if err != nil {
			log.Printf("Failed to connect to peer %s: %v", peerAddr, err)
		}
	}

	return nil
}

// handlePeerDiscovery handles peer discovery messages
func (n *P2PNode) handlePeerDiscovery(msg *Message) error {
	var peerInfo PeerInfo
	err := json.Unmarshal(msg.Data, &peerInfo)
	if err != nil {
		return fmt.Errorf("error unmarshaling peer discovery: %w", err)
	}

	log.Printf("Received peer discovery from %s", peerInfo.ID)

	// Add peer to our list
	n.mu.Lock()
	n.peers[peerInfo.ID] = &peerInfo
	n.mu.Unlock()

	return nil
}

// peerDiscoveryWorker periodically broadcasts peer discovery messages
func (n *P2PNode) peerDiscoveryWorker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n.broadcastPeerDiscovery()
		case <-n.ctx.Done():
			return
		}
	}
}

// broadcastPeerDiscovery broadcasts peer discovery information
func (n *P2PNode) broadcastPeerDiscovery() {
	peerInfo := &PeerInfo{
		ID:        n.host.ID(),
		Addresses: n.host.Addrs(),
		LastSeen:  time.Now(),
	}

	data, err := json.Marshal(peerInfo)
	if err != nil {
		log.Printf("Failed to marshal peer info: %v", err)
		return
	}

	msg := Message{
		Type:      "peer_discovery",
		Data:      data,
		Timestamp: time.Now().Unix(),
		Sender:    n.host.ID().String(),
	}

	msgData, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to marshal peer discovery message: %v", err)
		return
	}

	// Publish to node management topic
	if topic, exists := n.topics["/dyphira/node_management"]; exists {
		err = topic.Publish(n.ctx, msgData)
		if err != nil {
			log.Printf("Failed to publish peer discovery: %v", err)
		}
	}
}

// PublishBlock publishes a block to the network
func (n *P2PNode) PublishBlock(block *types.Block) error {
	topic, exists := n.topics["/dyphira/blocks"]
	if !exists {
		return fmt.Errorf("not subscribed to blocks topic")
	}

	msg := Message{
		Type:      "block",
		Timestamp: time.Now().Unix(),
		Sender:    n.host.ID().String(),
		Height:    block.Header.Height,
	}

	data, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}
	msg.Data = data

	msgData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return topic.Publish(n.ctx, msgData)
}

// PublishTransaction publishes a transaction to the network
func (n *P2PNode) PublishTransaction(tx *types.Transaction) error {
	topic, exists := n.topics["/dyphira/txs"]
	if !exists {
		return fmt.Errorf("not subscribed to transactions topic")
	}

	msg := Message{
		Type:      "transaction",
		Timestamp: time.Now().Unix(),
		Sender:    n.host.ID().String(),
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}
	msg.Data = data

	msgData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return topic.Publish(n.ctx, msgData)
}

// PublishApproval publishes an approval to the network
func (n *P2PNode) PublishApproval(approval *types.ConsensusMsg) error {
	topic, exists := n.topics["/dyphira/approvals"]
	if !exists {
		return fmt.Errorf("not subscribed to approvals topic")
	}

	msg := Message{
		Type:      "approval",
		Timestamp: time.Now().Unix(),
		Sender:    n.host.ID().String(),
		Height:    approval.Height,
	}

	data, err := json.Marshal(approval)
	if err != nil {
		return fmt.Errorf("failed to marshal approval: %w", err)
	}
	msg.Data = data

	msgData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return topic.Publish(n.ctx, msgData)
}

// PublishStateSyncResponse publishes a state sync response
func (n *P2PNode) PublishStateSyncResponse(response *StateSyncResponse, targetPeer peer.ID) error {
	topic, exists := n.topics["/dyphira/state_sync"]
	if !exists {
		return fmt.Errorf("not subscribed to state sync topic")
	}

	msg := Message{
		Type:      "state_sync_response",
		Timestamp: time.Now().Unix(),
		Sender:    n.host.ID().String(),
	}

	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal state sync response: %w", err)
	}
	msg.Data = data

	msgData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return topic.Publish(n.ctx, msgData)
}

// PublishNewNodeResponse publishes a new node response
func (n *P2PNode) PublishNewNodeResponse(response *NewNodeResponse, targetPeer peer.ID) error {
	topic, exists := n.topics["/dyphira/node_management"]
	if !exists {
		return fmt.Errorf("not subscribed to node management topic")
	}

	msg := Message{
		Type:      "new_node_response",
		Timestamp: time.Now().Unix(),
		Sender:    n.host.ID().String(),
	}

	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal new node response: %w", err)
	}
	msg.Data = data

	msgData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return topic.Publish(n.ctx, msgData)
}

// RequestStateSync requests state synchronization from peers
func (n *P2PNode) RequestStateSync(fromHeight, toHeight uint64) error {
	topic, exists := n.topics["/dyphira/state_sync"]
	if !exists {
		return fmt.Errorf("not subscribed to state sync topic")
	}

	request := &StateSyncRequest{
		FromHeight: fromHeight,
		ToHeight:   toHeight,
		Requester:  n.host.ID(),
	}

	msg := Message{
		Type:      "state_sync_request",
		Timestamp: time.Now().Unix(),
		Sender:    n.host.ID().String(),
	}

	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal state sync request: %w", err)
	}
	msg.Data = data

	msgData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	log.Printf("Requesting state sync for blocks %d-%d", fromHeight, toHeight)
	return topic.Publish(n.ctx, msgData)
}

// RequestJoinNetwork requests to join the network as a new node
func (n *P2PNode) RequestJoinNetwork() error {
	topic, exists := n.topics["/dyphira/node_management"]
	if !exists {
		return fmt.Errorf("not subscribed to node management topic")
	}

	request := &NewNodeRequest{
		NodeID:  n.host.ID(),
		Address: n.GetAddress(),
	}

	msg := Message{
		Type:      "new_node_request",
		Timestamp: time.Now().Unix(),
		Sender:    n.host.ID().String(),
	}

	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal new node request: %w", err)
	}
	msg.Data = data

	msgData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	log.Printf("Requesting to join network")
	return topic.Publish(n.ctx, msgData)
}

// ConnectToPeer connects to a peer
func (n *P2PNode) ConnectToPeer(addr string) error {
	maddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return fmt.Errorf("invalid multiaddr: %w", err)
	}

	peer, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return fmt.Errorf("failed to parse peer info: %w", err)
	}

	err = n.host.Connect(n.ctx, *peer)
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}

	log.Printf("Connected to peer %s", peer.ID)
	return nil
}

// GetPeers returns information about connected peers
func (n *P2PNode) GetPeers() []*PeerInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()

	peers := make([]*PeerInfo, 0, len(n.peers))
	for _, peer := range n.peers {
		peers = append(peers, peer)
	}
	return peers
}

// GetAddress returns the node's address
func (n *P2PNode) GetAddress() string {
	if len(n.host.Addrs()) == 0 {
		return ""
	}

	addr := n.host.Addrs()[0]
	return fmt.Sprintf("%s/p2p/%s", addr, n.host.ID())
}

// onPeerConnected handles peer connection events
func (n *P2PNode) onPeerConnected(net network.Network, conn network.Conn) {
	peerID := conn.RemotePeer()
	peerInfo := &PeerInfo{
		ID:        peerID,
		Addresses: []multiaddr.Multiaddr{conn.RemoteMultiaddr()},
		Protocols: []string{},
		LastSeen:  time.Now(),
		IsNew:     true, // Mark as new node
	}

	n.mu.Lock()
	n.peers[peerID] = peerInfo
	n.mu.Unlock()

	log.Printf("Peer connected: %s", peerID)

	// If this is a new node, send them our state
	if peerInfo.IsNew {
		go n.handleNewNodeJoin(peerID)
	}
}

// onPeerDisconnected handles peer disconnection events
func (n *P2PNode) onPeerDisconnected(net network.Network, conn network.Conn) {
	peerID := conn.RemotePeer()

	n.mu.Lock()
	delete(n.peers, peerID)
	n.mu.Unlock()

	log.Printf("Peer disconnected: %s", peerID)
}

// handleNewNodeJoin handles when a new node joins the network
func (n *P2PNode) handleNewNodeJoin(peerID peer.ID) {
	// Wait a bit for the connection to stabilize
	select {
	case <-n.ctx.Done():
		return // Context cancelled, don't proceed
	case <-time.After(2 * time.Second):
		// Continue after delay
	}

	// Send state sync request to get the new node up to date
	currentHeight := n.blockchain.GetLatestHeight()
	if currentHeight > 0 {
		err := n.RequestStateSync(0, currentHeight)
		if err != nil {
			log.Printf("Failed to request state sync for new node %s: %v", peerID, err)
		}
	}
}

// RandomSource implements crypto/rand.Source for libp2p
type RandomSource struct{}

func (r RandomSource) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}
