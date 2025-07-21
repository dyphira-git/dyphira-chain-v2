package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

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
	host   host.Host
	pubsub *ps.PubSub
	topics map[string]*ps.Topic
	subs   map[string]*ps.Subscription
	peers  map[peer.ID]*PeerInfo
	ctx    context.Context
	cancel context.CancelFunc
}

// PeerInfo represents information about a peer
type PeerInfo struct {
	ID        peer.ID
	Addresses []multiaddr.Multiaddr
	Protocols []string
	LastSeen  time.Time
}

// Message represents a network message
type Message struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp int64           `json:"timestamp"`
	Sender    string          `json:"sender"`
}

// NewP2PNode creates a new P2P node
func NewP2PNode(port int) (*P2PNode, error) {
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
		host:   host,
		pubsub: pubsub,
		topics: make(map[string]*ps.Topic),
		subs:   make(map[string]*ps.Subscription),
		peers:  make(map[peer.ID]*PeerInfo),
		ctx:    ctx,
		cancel: cancel,
	}

	// Set up network event handlers
	host.Network().Notify(&network.NotifyBundle{
		ConnectedF:    node.onPeerConnected,
		DisconnectedF: node.onPeerDisconnected,
	})

	return node, nil
}

// Start starts the P2P node
func (n *P2PNode) Start() error {
	// Join topics
	topics := []string{
		"/dyphira/blocks",
		"/dyphira/txs",
		"/dyphira/approvals",
	}

	for _, topicName := range topics {
		err := n.JoinTopic(topicName)
		if err != nil {
			return fmt.Errorf("failed to join topic %s: %w", topicName, err)
		}
	}

	log.Printf("P2P node started on %s", n.host.Addrs()[0])
	return nil
}

// Stop stops the P2P node
func (n *P2PNode) Stop() error {
	n.cancel()
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

		// Handle message based on topic
		switch topicName {
		case "/dyphira/blocks":
			n.handleBlockMessage(&networkMsg)
		case "/dyphira/txs":
			n.handleTransactionMessage(&networkMsg)
		case "/dyphira/approvals":
			n.handleApprovalMessage(&networkMsg)
		}
	}
}

// handleBlockMessage handles block messages
func (n *P2PNode) handleBlockMessage(msg *Message) {
	var block types.Block
	err := json.Unmarshal(msg.Data, &block)
	if err != nil {
		log.Printf("Error unmarshaling block: %v", err)
		return
	}

	log.Printf("Received block %d from %s", block.Header.Height, msg.Sender)
	// In practice, you'd forward this to the blockchain
}

// handleTransactionMessage handles transaction messages
func (n *P2PNode) handleTransactionMessage(msg *Message) {
	var tx types.Transaction
	err := json.Unmarshal(msg.Data, &tx)
	if err != nil {
		log.Printf("Error unmarshaling transaction: %v", err)
		return
	}

	log.Printf("Received transaction from %s", msg.Sender)
	// In practice, you'd add this to the mempool
}

// handleApprovalMessage handles approval messages
func (n *P2PNode) handleApprovalMessage(msg *Message) {
	var approval types.ConsensusMsg
	err := json.Unmarshal(msg.Data, &approval)
	if err != nil {
		log.Printf("Error unmarshaling approval: %v", err)
		return
	}

	log.Printf("Received approval for block %d from %s", approval.Height, msg.Sender)
	// In practice, you'd forward this to the consensus engine
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
	}

	n.peers[peerID] = peerInfo
	log.Printf("Peer connected: %s", peerID)
}

// onPeerDisconnected handles peer disconnection events
func (n *P2PNode) onPeerDisconnected(net network.Network, conn network.Conn) {
	peerID := conn.RemotePeer()
	delete(n.peers, peerID)
	log.Printf("Peer disconnected: %s", peerID)
}

// RandomSource implements crypto/rand.Source for libp2p
type RandomSource struct{}

func (r RandomSource) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}
