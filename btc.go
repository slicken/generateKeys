package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip32"
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
		// Use the custom path directly
		btc.derivationPath = customPath
	}

	// Derive child key using the updated derivation path
	childKey, err := btc.deriveChildKey(privateKey, btc.derivationPath)
	if err != nil {
		return nil, err
	}

	address, err := btc.getAddress(childKey)
	if err != nil {
		return nil, err
	}

	k := new(KeyPair)
	k.network = btc.name
	k.private = childKey.String()
	k.public = address.EncodeAddress()
	k.mnemonic = mnemonic
	k.derivationPath = btc.derivationPath

	return k, nil
}

func (btc bitcoin) deriveChildKey(parentKey *btcutil.WIF, path string) (*btcutil.WIF, error) {
	// Split the derivation path into components
	components := strings.Split(path, "/")
	// Remove the first "m" part of the path
	components = components[1:]

	// Convert the WIF private key to the raw private key
	privKeyBytes := parentKey.PrivKey.Serialize()

	// Create the master key from the raw private key
	masterKey, err := bip32.NewMasterKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error creating master key: %v", err)
	}

	// Iterate through the path components and derive child keys
	for _, component := range components {
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

		// Derive the child key at this index manually (using the package's Derive method if available)
		masterKey, err = masterKey.NewChildKey(uint32(index))
		if err != nil {
			return nil, fmt.Errorf("error deriving child key: %v", err)
		}
	}

	// Return the new WIF for the derived key
	secret := masterKey.Key

	// Convert the private key bytes into the correct format
	privKey, _ := btcec.PrivKeyFromBytes(secret)
	return btcutil.NewWIF(privKey, btc.getParams(), true)
}
