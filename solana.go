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

	k := new(KeyPair)
	k.network = "solana"
	//k.private = base64.StdEncoding.EncodeToString(wallet.PrivateKey)
	k.private = base58.Encode(wallet.PrivateKey)
	k.public = wallet.PublicKey.ToBase58()

	return k, nil
}
