package main

import (
	"github.com/blocto/solana-go-sdk/types"
	"github.com/btcsuite/btcd/btcutil/base58"
)

type solana struct{}

func (sol solana) Name() string {
	return "Solana"
}

// GenerateKeys for solana
func (sol solana) GenerateKeys() (*KeyPair, error) {
	wallet := types.NewAccount()

	return &KeyPair{
		network: "solana",
		private: base58.Encode(wallet.PrivateKey),
		public:  wallet.PublicKey.ToBase58(),
	}, nil
}
