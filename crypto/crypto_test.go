package crypto

import (
	"testing"
)

func TestPubToAddressWhirlpoolRipemd160(t *testing.T) {
	// Test with a known public key
	testPubKey := []byte("test public key for whirlpool ripemd160 hashing")

	// Generate address using new method
	address := PubToAddress(testPubKey)

	// Verify address is not zero
	if address == [20]byte{} {
		t.Error("Generated address is zero")
	}

	// Verify address length
	if len(address) != 20 {
		t.Errorf("Expected address length 20, got %d", len(address))
	}

	t.Logf("Generated address: %s", address.String())
}

func TestBech32Encoding(t *testing.T) {
	// Generate a key pair
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Get both address formats
	hexAddress := keyPair.GetAddress()
	bech32Address, err := keyPair.GetBech32Address()
	if err != nil {
		t.Fatalf("Failed to get Bech32 address: %v", err)
	}

	// Verify Bech32 address starts with "dyp_"
	if len(bech32Address) == 0 || bech32Address[:4] != "dyp_" {
		t.Errorf("Bech32 address should start with 'dyp_', got: %s", bech32Address)
	}

	// Test round-trip conversion
	decodedAddress, err := Bech32ToAddress(bech32Address)
	if err != nil {
		t.Fatalf("Failed to decode Bech32 address: %v", err)
	}

	if decodedAddress != hexAddress {
		t.Errorf("Round-trip conversion failed: original=%s, decoded=%s",
			hexAddress.String(), decodedAddress.String())
	}

	t.Logf("Hex address: %s", hexAddress.String())
	t.Logf("Bech32 address: %s", bech32Address)
}

func TestAddressParsing(t *testing.T) {
	// Generate a key pair
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	hexAddress := keyPair.GetAddress()
	bech32Address, err := keyPair.GetBech32Address()
	if err != nil {
		t.Fatalf("Failed to get Bech32 address: %v", err)
	}

	// Test parsing hex address
	parsedHex, err := AddressFromString(hexAddress.String())
	if err != nil {
		t.Fatalf("Failed to parse hex address: %v", err)
	}
	if parsedHex != hexAddress {
		t.Errorf("Hex address parsing failed: expected=%s, got=%s",
			hexAddress.String(), parsedHex.String())
	}

	// Test parsing Bech32 address
	parsedBech32, err := Bech32ToAddress(bech32Address)
	if err != nil {
		t.Fatalf("Failed to parse Bech32 address: %v", err)
	}
	if parsedBech32 != hexAddress {
		t.Errorf("Bech32 address parsing failed: expected=%s, got=%s",
			hexAddress.String(), parsedBech32.String())
	}
}

func TestWhirlpoolRipemd160Consistency(t *testing.T) {
	// Test that the same input produces the same output
	testData := []byte("consistent hashing test")

	address1 := PubToAddress(testData)
	address2 := PubToAddress(testData)

	if address1 != address2 {
		t.Errorf("Inconsistent hashing: %s != %s",
			address1.String(), address2.String())
	}

	// Test that different inputs produce different outputs
	testData2 := []byte("different input")
	address3 := PubToAddress(testData2)

	if address1 == address3 {
		t.Error("Different inputs produced the same address")
	}
}
