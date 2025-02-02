package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/blocto/solana-go-sdk/types"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

type solana struct{}

func (sol solana) Name() string {
	return "Solana"
}

// GenerateKeys for Solana
func (sol solana) GenerateKeys() (*KeyPair, error) {
	var wallet types.Account
	var mnemonic string
	var err error

	// Check if a custom mnemonic is provided
	if customMnemonic != "" {
		// Validate the mnemonic
		if !bip39.IsMnemonicValid(customMnemonic) {
			return nil, fmt.Errorf("invalid mnemonic phrase")
		}

		// Use the custom mnemonic
		mnemonic = customMnemonic
	} else {
		// Generate a new mnemonic if no custom mnemonic is provided and -a/--all is set
		if *infoFlag || *infoLongFlag {
			entropy, err := bip39.NewEntropy(128) // 128 bits of entropy for a 12-word mnemonic
			if err != nil {
				return nil, fmt.Errorf("failed to generate entropy: %v", err)
			}

			mnemonic, err = bip39.NewMnemonic(entropy)
			if err != nil {
				return nil, fmt.Errorf("failed to generate mnemonic: %v", err)
			}
		} else {
			// Generate a new wallet with a random mnemonic (not exposed unless -a/--all is set)
			wallet = types.NewAccount()
			return &KeyPair{
				network:  "solana",
				private:  base58.Encode(wallet.PrivateKey),
				public:   wallet.PublicKey.ToBase58(),
				mnemonic: "", // No mnemonic unless -a/--all is set
			}, nil
		}
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, "") // No passphrase for simplicity

	// Derive the private key using BIP-44 derivation path
	privateKey, err := deriveSolanaPrivateKey(seed, customPath)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %v", err)
	}

	// Create a Solana wallet from the private key
	wallet, err = types.AccountFromSeed(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet from seed: %v", err)
	}

	// Include the mnemonic in the KeyPair if -a/--all is set or a custom mnemonic is provided
	var keyPairMnemonic string
	if *infoFlag || *infoLongFlag || customMnemonic != "" {
		keyPairMnemonic = mnemonic
	}

	// Set the derivation path
	derivationPath := customPath
	if derivationPath == "" {
		derivationPath = "m/44'/501'/0'/0'" // Default Solana BIP-44 derivation path
	}

	return &KeyPair{
		network:        "solana",
		private:        base58.Encode(wallet.PrivateKey),
		public:         wallet.PublicKey.ToBase58(),
		mnemonic:       keyPairMnemonic,
		derivationPath: derivationPath,
	}, nil
}

// deriveSolanaPrivateKey derives the private key from the seed using the BIP-44 derivation path
func deriveSolanaPrivateKey(seed []byte, customPath string) ([]byte, error) {
	// Default Solana BIP-44 derivation path
	derivationPath := "m/44'/501'/0'/0'"
	if customPath != "" {
		derivationPath = customPath
	}

	// Split the derivation path into components
	components := strings.Split(derivationPath, "/")
	if components[0] != "m" {
		return nil, fmt.Errorf("invalid derivation path: must start with 'm'")
	}

	// Create the master key from the seed
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %v", err)
	}

	// Iterate through the path components and derive child keys
	currentKey := masterKey
	for _, component := range components[1:] {
		// Check if the component is hardened (ends with a single quote)
		hardened := false
		if strings.HasSuffix(component, "'") {
			hardened = true
			component = strings.TrimSuffix(component, "'")
		}

		// Convert component to uint32
		index, err := strconv.ParseUint(component, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid index in derivation path: %v", err)
		}

		// Harden the index if needed (add 0x80000000 for hardened)
		if hardened {
			index += 0x80000000
		}

		// Derive the child key at this index
		currentKey, err = currentKey.NewChildKey(uint32(index))
		if err != nil {
			return nil, fmt.Errorf("failed to derive child key: %v", err)
		}
	}

	// Return the private key bytes
	return currentKey.Key, nil
}
