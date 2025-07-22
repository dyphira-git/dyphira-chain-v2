package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jzelinskie/whirlpool"
	"golang.org/x/crypto/ripemd160"
)

// Address represents a 20-byte Dyphira address
type Address [20]byte

// Hash represents a 32-byte hash
type Hash [32]byte

// Signature represents an ECDSA signature
type Signature struct {
	V uint8
	R [32]byte
	S [32]byte
}

// KeyPair represents a public/private key pair
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// GenerateKeyPair generates a new secp256k1 key pair
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey := &privateKey.PublicKey
	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// KeyPairFromPrivateKey creates a KeyPair from private key bytes
func KeyPairFromPrivateKey(privateKeyBytes []byte) (*KeyPair, error) {
	if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privateKeyBytes))
	}

	privateKey := new(ecdsa.PrivateKey)
	privateKey.PublicKey.Curve = crypto.S256()
	privateKey.D = new(big.Int).SetBytes(privateKeyBytes)

	// Compute public key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privateKeyBytes)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// PubToAddress derives an address from a public key using Whirlpool + RIPEMD160
func PubToAddress(pubKey []byte) Address {
	// First hash with Whirlpool
	whirlpoolHash := whirlpool.New()
	whirlpoolHash.Write(pubKey)
	whirlpoolResult := whirlpoolHash.Sum(nil)

	// Take the first 256 bits (32 bytes) from Whirlpool result
	whirlpool256 := whirlpoolResult[:32]

	// Then hash with RIPEMD160
	ripemd160Hash := ripemd160.New()
	ripemd160Hash.Write(whirlpool256)
	ripeHash := ripemd160Hash.Sum(nil)

	// RIPEMD160 produces exactly 20 bytes, use all of them
	var address Address
	copy(address[:], ripeHash)
	return address
}

// GetAddress returns the address for a key pair
func (kp *KeyPair) GetAddress() Address {
	pubKeyBytes := crypto.CompressPubkey(kp.PublicKey)
	return PubToAddress(pubKeyBytes)
}

// GetBech32Address returns the Bech32 encoded address for a key pair
func (kp *KeyPair) GetBech32Address() (string, error) {
	address := kp.GetAddress()
	return AddressToBech32(address, "dyp_")
}

// AddressToBech32 converts an address to Bech32 format
func AddressToBech32(address Address, hrp string) (string, error) {
	// Convert address bytes to 5-bit groups for Bech32
	converted, err := bech32.ConvertBits(address[:], 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert address bits: %w", err)
	}

	// Encode to Bech32
	encoded, err := bech32.Encode(hrp, converted)
	if err != nil {
		return "", fmt.Errorf("failed to encode address: %w", err)
	}

	return encoded, nil
}

// Bech32ToAddress converts a Bech32 address back to Address type
func Bech32ToAddress(bech32Addr string) (Address, error) {
	// Decode Bech32
	hrp, data, err := bech32.Decode(bech32Addr)
	if err != nil {
		return Address{}, fmt.Errorf("failed to decode bech32 address: %w", err)
	}

	// Verify HRP
	if hrp != "dyp_" {
		return Address{}, fmt.Errorf("invalid HRP: expected 'dyp_', got '%s'", hrp)
	}

	// Convert 5-bit groups back to 8-bit bytes
	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return Address{}, fmt.Errorf("failed to convert address bits: %w", err)
	}

	// Verify length
	if len(converted) != 20 {
		return Address{}, fmt.Errorf("invalid address length: %d", len(converted))
	}

	var address Address
	copy(address[:], converted)
	return address, nil
}

// SignHash signs a hash with the private key
func (kp *KeyPair) SignHash(hash Hash) (*Signature, error) {
	signature, err := crypto.Sign(hash[:], kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %w", err)
	}

	// Parse signature components
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	v := signature[64] + 27

	// Convert to 32-byte arrays with proper padding
	var rBytes, sBytes [32]byte
	rBytesSlice := r.Bytes()
	sBytesSlice := s.Bytes()

	// Copy bytes from right to left to maintain proper alignment
	copy(rBytes[32-len(rBytesSlice):], rBytesSlice)
	copy(sBytes[32-len(sBytesSlice):], sBytesSlice)

	return &Signature{
		V: v,
		R: rBytes,
		S: sBytes,
	}, nil
}

// VerifySignature verifies a signature against a hash and public key
func VerifySignature(hash Hash, sig *Signature, pubKey []byte) bool {
	// Convert signature to ECDSA format
	r := new(big.Int).SetBytes(sig.R[:])
	s := new(big.Int).SetBytes(sig.S[:])

	// Parse public key
	ecdsaPubKey, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		return false
	}

	// Verify signature
	return ecdsa.Verify(ecdsaPubKey, hash[:], r, s)
}

// Ecrecover recovers the public key from a signature
func Ecrecover(hash []byte, sig []byte, v uint8) ([]byte, error) {
	// Convert signature to ECDSA format
	if len(sig) != 64 {
		return nil, fmt.Errorf("invalid signature length: %d", len(sig))
	}

	// Recover public key
	pubKey, err := crypto.SigToPub(hash, append(sig, v-27))
	if err != nil {
		return nil, fmt.Errorf("failed to recover public key: %w", err)
	}

	return crypto.CompressPubkey(pubKey), nil
}

// CalculateHash calculates SHA256 hash of data
func CalculateHash(data []byte) Hash {
	hash := sha256.Sum256(data)
	return hash
}

// String returns hex representation of address
func (a Address) String() string {
	return hex.EncodeToString(a[:])
}

// String returns hex representation of hash
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// Bytes returns address as byte slice
func (a Address) Bytes() []byte {
	return a[:]
}

// Bytes returns hash as byte slice
func (h Hash) Bytes() []byte {
	return h[:]
}

// AddressFromString parses address from hex string
func AddressFromString(s string) (Address, error) {
	var addr Address
	data, err := hex.DecodeString(s)
	if err != nil {
		return addr, fmt.Errorf("invalid address format: %w", err)
	}
	if len(data) != 20 {
		return addr, fmt.Errorf("invalid address length: %d", len(data))
	}
	copy(addr[:], data)
	return addr, nil
}

// HashFromString parses hash from hex string
func HashFromString(s string) (Hash, error) {
	var hash Hash
	data, err := hex.DecodeString(s)
	if err != nil {
		return hash, fmt.Errorf("invalid hash format: %w", err)
	}
	if len(data) != 32 {
		return hash, fmt.Errorf("invalid hash length: %d", len(data))
	}
	copy(hash[:], data)
	return hash, nil
}

// MarshalJSON custom marshaling for Address to hex string
func (a Address) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON custom unmarshaling for Address from hex string
func (a *Address) UnmarshalJSON(data []byte) error {
	var hexStr string
	if err := json.Unmarshal(data, &hexStr); err != nil {
		return err
	}

	addr, err := AddressFromString(hexStr)
	if err != nil {
		return err
	}

	*a = addr
	return nil
}

// MarshalJSON custom marshaling for Hash to hex string
func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}

// UnmarshalJSON custom unmarshaling for Hash from hex string
func (h *Hash) UnmarshalJSON(data []byte) error {
	var hexStr string
	if err := json.Unmarshal(data, &hexStr); err != nil {
		return err
	}

	hash, err := HashFromString(hexStr)
	if err != nil {
		return err
	}

	*h = hash
	return nil
}
