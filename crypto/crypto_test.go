package crypto

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)
	assert.NotNil(t, keyPair.PrivateKey)
	assert.NotNil(t, keyPair.PublicKey)
	assert.Equal(t, keyPair.PrivateKey.PublicKey, *keyPair.PublicKey)
}

func TestKeyPairFromPrivateKey(t *testing.T) {
	// Generate a key pair first
	originalKeyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	// Extract private key bytes
	privateKeyBytes := originalKeyPair.PrivateKey.D.Bytes()

	// Create new key pair from private key bytes
	newKeyPair, err := KeyPairFromPrivateKey(privateKeyBytes)
	require.NoError(t, err)

	// Verify they are the same
	assert.Equal(t, originalKeyPair.PrivateKey.D, newKeyPair.PrivateKey.D)
	assert.Equal(t, originalKeyPair.PublicKey.X, newKeyPair.PublicKey.X)
	assert.Equal(t, originalKeyPair.PublicKey.Y, newKeyPair.PublicKey.Y)
}

func TestKeyPairFromPrivateKeyInvalidLength(t *testing.T) {
	invalidKey := []byte{1, 2, 3} // Too short
	_, err := KeyPairFromPrivateKey(invalidKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key length")
}

func TestPubToAddress(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	pubKeyBytes := crypto.CompressPubkey(keyPair.PublicKey)
	address := PubToAddress(pubKeyBytes)

	// Verify address is not zero
	assert.NotEqual(t, Address{}, address)

	// Verify address length
	assert.Equal(t, 20, len(address))
}

func TestGetAddress(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	address := keyPair.GetAddress()
	assert.NotEqual(t, Address{}, address)
	assert.Equal(t, 20, len(address))
}

func TestGetBech32Address(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	bech32Addr, err := keyPair.GetBech32Address()
	require.NoError(t, err)

	// Verify it starts with the correct prefix
	assert.True(t, len(bech32Addr) > 0)
	assert.Contains(t, bech32Addr, "dyp_")
}

func TestAddressToBech32(t *testing.T) {
	// Create a test address
	var address Address
	for i := range address {
		address[i] = byte(i)
	}

	bech32Addr, err := AddressToBech32(address, "dyp_")
	require.NoError(t, err)

	assert.True(t, len(bech32Addr) > 0)
	assert.Contains(t, bech32Addr, "dyp_")
}

func TestBech32ToAddress(t *testing.T) {
	// Create a test address
	var originalAddress Address
	for i := range originalAddress {
		originalAddress[i] = byte(i)
	}

	bech32Addr, err := AddressToBech32(originalAddress, "dyp_")
	require.NoError(t, err)

	// Convert back
	convertedAddress, err := Bech32ToAddress(bech32Addr)
	require.NoError(t, err)

	assert.Equal(t, originalAddress, convertedAddress)
}

func TestBech32ToAddressInvalid(t *testing.T) {
	_, err := Bech32ToAddress("invalid_address")
	assert.Error(t, err)
}

func TestSignHash(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	// Create a test hash
	var hash Hash
	for i := range hash {
		hash[i] = byte(i)
	}

	signature, err := keyPair.SignHash(hash)
	require.NoError(t, err)

	assert.NotZero(t, signature.V)
	assert.NotEqual(t, [32]byte{}, signature.R)
	assert.NotEqual(t, [32]byte{}, signature.S)
}

func TestVerifySignature(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	// Create a test hash
	var hash Hash
	for i := range hash {
		hash[i] = byte(i)
	}

	// Sign the hash
	signature, err := keyPair.SignHash(hash)
	require.NoError(t, err)

	// Get public key bytes (uncompressed for verification)
	pubKeyBytes := crypto.FromECDSAPub(keyPair.PublicKey)

	// Verify signature
	isValid := VerifySignature(hash, signature, pubKeyBytes)
	assert.True(t, isValid)
}

func TestVerifySignatureInvalid(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	// Create a test hash
	var hash Hash
	for i := range hash {
		hash[i] = byte(i)
	}

	// Create an invalid signature
	invalidSig := &Signature{
		V: 27,
		R: [32]byte{},
		S: [32]byte{},
	}

	// Get public key bytes (uncompressed for verification)
	pubKeyBytes := crypto.FromECDSAPub(keyPair.PublicKey)

	// Verify signature should fail
	isValid := VerifySignature(hash, invalidSig, pubKeyBytes)
	assert.False(t, isValid)
}

func TestEcrecover(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	require.NoError(t, err)

	// Create a test hash
	var hash Hash
	for i := range hash {
		hash[i] = byte(i)
	}

	// Sign the hash
	signature, err := keyPair.SignHash(hash)
	require.NoError(t, err)

	// Recover public key
	sigBytes := append(signature.R[:], signature.S[:]...)
	recoveredPubKey, err := Ecrecover(hash[:], sigBytes, signature.V)
	require.NoError(t, err)

	// Verify recovered public key matches original
	originalPubKey := crypto.CompressPubkey(keyPair.PublicKey)
	assert.Equal(t, originalPubKey, recoveredPubKey)
}

func TestCalculateHash(t *testing.T) {
	data := []byte("test data")
	hash := CalculateHash(data)

	assert.NotEqual(t, Hash{}, hash)
	assert.Equal(t, 32, len(hash))
}

func TestAddressString(t *testing.T) {
	var address Address
	for i := range address {
		address[i] = byte(i)
	}

	hexStr := address.String()
	assert.True(t, len(hexStr) == 40) // 20 bytes = 40 hex chars
	assert.Equal(t, "000102030405060708090a0b0c0d0e0f10111213", hexStr)
}

func TestHashString(t *testing.T) {
	var hash Hash
	for i := range hash {
		hash[i] = byte(i)
	}

	hexStr := hash.String()
	assert.True(t, len(hexStr) == 64) // 32 bytes = 64 hex chars
	assert.Equal(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", hexStr)
}

func TestAddressBytes(t *testing.T) {
	var address Address
	for i := range address {
		address[i] = byte(i)
	}

	bytes := address.Bytes()
	assert.Equal(t, 20, len(bytes))
	assert.Equal(t, address[:], bytes)
}

func TestHashBytes(t *testing.T) {
	var hash Hash
	for i := range hash {
		hash[i] = byte(i)
	}

	bytes := hash.Bytes()
	assert.Equal(t, 32, len(bytes))
	assert.Equal(t, hash[:], bytes)
}

func TestAddressFromString(t *testing.T) {
	hexStr := "000102030405060708090a0b0c0d0e0f10111213"
	address, err := AddressFromString(hexStr)
	require.NoError(t, err)

	var expected Address
	for i := range expected {
		expected[i] = byte(i)
	}
	assert.Equal(t, expected, address)
}

func TestAddressFromStringInvalid(t *testing.T) {
	_, err := AddressFromString("invalid_hex")
	assert.Error(t, err)
}

func TestHashFromString(t *testing.T) {
	hexStr := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	hash, err := HashFromString(hexStr)
	require.NoError(t, err)

	var expected Hash
	for i := range expected {
		expected[i] = byte(i)
	}
	assert.Equal(t, expected, hash)
}

func TestHashFromStringInvalid(t *testing.T) {
	_, err := HashFromString("invalid_hex")
	assert.Error(t, err)
}

func TestAddressMarshalJSON(t *testing.T) {
	var address Address
	for i := range address {
		address[i] = byte(i)
	}

	jsonBytes, err := address.MarshalJSON()
	require.NoError(t, err)

	expected := `"000102030405060708090a0b0c0d0e0f10111213"`
	assert.Equal(t, expected, string(jsonBytes))
}

func TestAddressUnmarshalJSON(t *testing.T) {
	jsonStr := `"000102030405060708090a0b0c0d0e0f10111213"`
	var address Address

	err := address.UnmarshalJSON([]byte(jsonStr))
	require.NoError(t, err)

	var expected Address
	for i := range expected {
		expected[i] = byte(i)
	}
	assert.Equal(t, expected, address)
}

func TestHashMarshalJSON(t *testing.T) {
	var hash Hash
	for i := range hash {
		hash[i] = byte(i)
	}

	jsonBytes, err := hash.MarshalJSON()
	require.NoError(t, err)

	expected := `"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"`
	assert.Equal(t, expected, string(jsonBytes))
}

func TestHashUnmarshalJSON(t *testing.T) {
	jsonStr := `"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"`
	var hash Hash

	err := hash.UnmarshalJSON([]byte(jsonStr))
	require.NoError(t, err)

	var expected Hash
	for i := range expected {
		expected[i] = byte(i)
	}
	assert.Equal(t, expected, hash)
}
