package main

import (
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

type bitcoin struct {
	name           string
	xpub           byte
	xpriv          byte
	isSegWit       bool
	isNative       bool
	derivationPath string
}

func (btc bitcoin) Name() string {
	return btc.name
}

var btcMap = map[string]bitcoin{
	"legacy": {name: "bitcoin legacy", xpub: 0x00, xpriv: 0x80, isSegWit: false, isNative: false, derivationPath: "m/44'/0'/0'/0/0"},
	"segwit": {name: "bitcoin segwit", xpub: 0x05, xpriv: 0x80, isSegWit: true, isNative: false, derivationPath: "m/49'/0'/0'/0/0"},
	"native": {name: "bitcoin native", xpub: 0x05, xpriv: 0x80, isSegWit: true, isNative: true, derivationPath: "m/84'/0'/0'/0/0"},
}

func (btc bitcoin) getParams() *chaincfg.Params {
	param := &chaincfg.MainNetParams // Always use mainnet
	if btc.isSegWit {
		if btc.isNative {
			param.Bech32HRPSegwit = "bc" // Native SegWit Bech32 address prefix (mainnet)
		} else {
			param.PubKeyHashAddrID = 0x00 // SegWit P2SH address prefix (mainnet)
		}
		param.PrivateKeyID = 0x80 // SegWit private key prefix (mainnet)
	} else {
		param.PubKeyHashAddrID = 0x00 // Legacy P2PKH address prefix (mainnet)
		param.PrivateKeyID = 0x80     // Legacy private key prefix (mainnet)
	}
	return param
}

func (btc bitcoin) createPrivateKey() (*btcutil.WIF, error) {
	// Generate a new private key (mainnet)
	secret, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	// Ensure it's for mainnet (not testnet) with the correct prefix
	return btcutil.NewWIF(secret, btc.getParams(), true)
}

// GetAddress will generate either a P2PKH or P2WPKH address depending on the flags
func (btc bitcoin) getAddress(wif *btcutil.WIF) (btcutil.Address, error) {
	pubKey := wif.PrivKey.PubKey()

	// Generate Native Segwit (starts with 'bc1')
	if btc.isNative {
		addr, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pubKey.SerializeCompressed()), btc.getParams())
		if err != nil {
			return nil, err
		}
		return addr, nil
	}

	// Generate Segwit integrated withness (starts with '3')
	if btc.isSegWit {
		addr, err := btcutil.NewAddressScriptHash(btcutil.Hash160(pubKey.SerializeCompressed()), btc.getParams())
		if err != nil {
			return nil, err
		}
		return addr, nil
	}

	// Otherwise, generate a legacy P2PKH address (starts with '1')
	addr, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pubKey.SerializeCompressed()), btc.getParams())
	if err != nil {
		return nil, err
	}
	return addr, nil
}

func (btc bitcoin) GenerateKeys() (*KeyPair, error) {
	if btc.name == "" {
		return nil, errors.New("network not found")
	}

	var privateKey *btcutil.WIF
	var mnemonic string
	var err error

	// If a custom mnemonic is provided, use it
	if customMnemonic != "" {
		mnemonic = customMnemonic
		// Generate seed from the custom mnemonic
		seed := bip39.NewSeed(mnemonic, "")
		secret, _ := btcec.PrivKeyFromBytes(seed[:32])
		privateKey, err = btcutil.NewWIF(secret, btc.getParams(), true)
		if err != nil {
			return nil, err
		}
		// fmt.Printf("Using custom mnemonic: %s\n", mnemonic) // Print the custom mnemonic being used
	} else if *infoFlag || *infoLongFlag {
		// If mnemonic flag is used, generate a random mnemonic
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return nil, err
		}
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
		seed := bip39.NewSeed(mnemonic, "")
		secret, _ := btcec.PrivKeyFromBytes(seed[:32])
		privateKey, err = btcutil.NewWIF(secret, btc.getParams(), true)
		if err != nil {
			return nil, err
		}
	} else {
		// If no mnemonic flag is used, generate a new private key
		privateKey, err = btc.createPrivateKey()
		if err != nil {
			return nil, err
		}
	}

	// Apply the custom derivation path if it's provided
	if customPath != "" {
		btc.derivationPath = customPath
		// fmt.Printf("Using custom derivation path: %s\n", customPath) // Print the custom derivation path being used
	}

	address, err := btc.getAddress(privateKey)
	if err != nil {
		return nil, err
	}

	k := new(KeyPair)
	k.network = btc.name
	k.private = privateKey.String()
	k.public = address.EncodeAddress()
	k.mnemonic = mnemonic
	k.derivationPath = btc.derivationPath

	return k, nil
}
