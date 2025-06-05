package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

type ethereum struct{}

func (eth ethereum) Name() string {
	return "Ethereum"
}

// parseDerivationPath parses a BIP-44 derivation path string into a slice of uint32 segments.
func parseDerivationPath(path string) ([]uint32, error) {
	segments := strings.Split(path, "/")
	if len(segments) < 2 || segments[0] != "m" {
		return nil, fmt.Errorf("invalid derivation path: %s", path)
	}

	var result []uint32
	for _, segment := range segments[1:] {
		// Handle hardened segments (e.g., 44')
		hardened := strings.HasSuffix(segment, "'")
		segment = strings.TrimSuffix(segment, "'")

		index, err := strconv.Atoi(segment)
		if err != nil {
			return nil, fmt.Errorf("invalid segment in derivation path: %s", segment)
		}

		if hardened {
			index += 0x80000000 // Add hardened flag
		}

		result = append(result, uint32(index))
	}

	return result, nil
}

// GenerateKeys for eth
func (eth ethereum) GenerateKeys() (*KeyPair, error) {
	var privateKey *ecdsa.PrivateKey
	var mnemonic string
	var derivationPath string
	var err error

	// If the mnemonic flag is set, generate mnemonic and derive the key pair
	if *infoFlag || *infoLongFlag || customMnemonic != "" {
		if customMnemonic != "" {
			mnemonic = customMnemonic
		} else {
			entropy, err := bip39.NewEntropy(256)
			if err != nil {
				return nil, err
			}
			mnemonic, err = bip39.NewMnemonic(entropy)
			if err != nil {
				return nil, err
			}
		}

		seed := bip39.NewSeed(mnemonic, "")

		// Derive the master key
		masterKey, err := bip32.NewMasterKey(seed)
		if err != nil {
			return nil, err
		}

		// Default BIP-44 path for Ethereum: m/44'/60'/0'/0/0
		defaultPath := []uint32{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0}
		derivationPath = "m/44'/60'/0'/0/0"

		// If a custom derivation path is provided, use it
		if customPath != "" {
			defaultPath, err = parseDerivationPath(customPath)
			if err != nil {
				return nil, err
			}
			derivationPath = customPath
		}

		// Derive the key using the specified path
		childKey := masterKey
		for _, segment := range defaultPath {
			childKey, err = childKey.NewChildKey(segment)
			if err != nil {
				return nil, err
			}
		}

		privateKey, err = crypto.ToECDSA(childKey.Key)
		if err != nil {
			return nil, err
		}
	} else {
		privateKey, err = crypto.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])

	return &KeyPair{
		network:        "ethereum",
		private:        hexutil.Encode(privateKeyBytes)[2:],
		public:         hexutil.Encode(hash.Sum(nil)[12:]),
		mnemonic:       mnemonic,
		derivationPath: derivationPath,
	}, nil
}

// GenerateFromPrivateKey generates the key pair from the provided private key hex string.
func (eth ethereum) GenerateFromPrivateKey(privateKeyHex string) (*KeyPair, error) {
	// Remove "0x" prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	// Decode hex private key
	privateKeyBytes, err := hexutil.Decode("0x" + privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key format: %v", err)
	}

	// Create private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}

	// Generate public key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	// Get public key bytes
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	// Generate Ethereum address
	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])

	return &KeyPair{
		network: "ethereum",
		private: privateKeyHex,
		public:  hexutil.Encode(hash.Sum(nil)[12:]),
	}, nil
}
