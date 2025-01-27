package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/blocto/solana-go-sdk/types"
	"github.com/btcsuite/btcd/btcutil/base58"
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

	// Derive the private key using SHA-256 (Phantom Wallet's method)
	hash := sha256.Sum256(seed)
	privateKey := hash[:32] // Use the first 32 bytes as the private key

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

	return &KeyPair{
		network:  "solana",
		private:  base58.Encode(wallet.PrivateKey),
		public:   wallet.PublicKey.ToBase58(),
		mnemonic: keyPairMnemonic, // Include the mnemonic in the KeyPair
	}, nil
}
