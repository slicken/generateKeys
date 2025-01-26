package main

import (
	"crypto/ecdsa"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

type ethereum struct{}

func (eth ethereum) Name() string {
	return "Ethereum"
}

// GenerateKeys for eth
func (eth ethereum) GenerateKeys() (*KeyPair, error) {
	var privateKey *ecdsa.PrivateKey
	var mnemonic string
	var err error

	// If the mnemonic flag is set, generate mnemonic and derive the key pair
	if *infoFlag || *infoLongFlag {
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return nil, err
		}
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
		seed := bip39.NewSeed(mnemonic, "")
		privateKey, err = crypto.ToECDSA(seed[:32])
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

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	_ = address

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])

	return &KeyPair{
		network:  "ethereum",
		private:  hexutil.Encode(privateKeyBytes)[2:],
		public:   hexutil.Encode(hash.Sum(nil)[12:]),
		mnemonic: mnemonic,
	}, nil
}
