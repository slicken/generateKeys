package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

type KeyPair struct {
	network        string
	public         string
	private        string
	mnemonic       string
	derivationPath string
}

//                 btct | taproot       Taproot (P2TR, Bech32m): Latest upgrade, enhanced privacy, improved efficiency, using Bech32m format.

func Usage() {
	fmt.Printf(`Usage: %s <NETWORK> [OPTION]

Generate key pairs for Bitcoin, Ethereum, and Solana.

Network (required):
  btc, legacy              Legacy (P2PKH): Oldest type, less efficient, higher fees.
  btcs, segwit             SegWit (P2SH-wrapped P2WPKH): SegWit compatibility, lower fees.
  btcn, native             Native SegWit (P2WPKH, Bech32): More efficient and secure, lower fees.
  eth, ethereum            Ethereum
  sol, solana              Solana

Option:
  -m, --mnemonic           Prints mnemonic for the wallet.
  -i, --include <include>  Include words in public key (comma-separated).
      --prefix             Addon for include.
      --postfix            Addon for include.
                           Example: -i abcde,10000
  -h, --help               Show this help message.

`, os.Args[0])
	os.Exit(1)
}

// Print to std.out
func (k KeyPair) Print() {
	fmt.Printf("%-3s %-12s %s\n", k.network, "public", k.public)
	fmt.Printf("%-3s %-12s %s\n", k.network, "private", k.private)
	if k.mnemonic != "" {
		fmt.Printf("%-3s %-12s %s\n", k.network, "mnemonic", k.mnemonic)
		if k.derivationPath != "" {
			fmt.Printf("%-3s %-12s %s\n", k.network, "derivation", k.derivationPath)
		}
	}
}

type Network interface {
	Name() string
	GenerateKeys() (*KeyPair, error)
}

var (
	includeFlag     = flag.String("i", "", "A comma-separated list of characters or words that the public key should include.")
	includeLongFlag = flag.String("include", "", "A comma-separated list of characters or words that the public key should include.")
	preFlag         = flag.Bool("prefix", false, "Addon to include flag.")
	postFlag        = flag.Bool("postfix", false, "Addon to include flag.")

	mnemonicFlag     = flag.Bool("m", false, "A boolean flag to generate and print a mnemonic.")
	mnemonicLongFlag = flag.Bool("mnemonic", false, "A boolean flag to generate and print a mnemonic.")
)

func main() {
	flag.Usage = Usage

	// Manually parse the arguments to separate the network argument from the flags
	args := os.Args[1:]
	var networkArg string
	var flagArgs []string

	for _, arg := range args {
		switch strings.ToLower(arg) {
		case "btc", "legacy", "btcs", "segwit", "btcn", "native", "eth", "ethereum", "sol", "solana":
			networkArg = arg
		default:
			flagArgs = append(flagArgs, arg)
		}
	}

	if networkArg == "" {
		Usage()
	}

	flag.CommandLine.Parse(flagArgs)

	var network Network

	switch strings.ToLower(networkArg) {
	case "btc", "legacy", "bitcoin":
		network = btcMap["legacy"]
	case "btcs", "segwit":
		network = btcMap["segwit"]
	case "btcn", "native":
		network = btcMap["native"]
	case "eth", "ethereum":
		network = &ethereum{}
	case "sol", "solana":
		network = &solana{}
	default:
		log.Fatalf("%q not found\n", networkArg)
	}

	include := *includeFlag
	if *includeLongFlag != "" {
		include = *includeLongFlag
	}

	includeWords := strings.Split(include, ",")
	if include != "" && len(includeWords) == 0 {
		log.Fatalln("no words to include")
	}

	// If we just want to generate a keypair without include logic
	if include == "" {
		keyPair, err := network.GenerateKeys()
		if err != nil {
			log.Fatalln(networkArg, err)
		}
		keyPair.Print()
		return
	}

	// If the -i or --include flag is present, generate keys and check for inclusion
	fmt.Printf("Generating %s keys that includes %s\n", network.Name(), includeWords)

	var count int
	for {
		keyPair, err := network.GenerateKeys()
		if err != nil {
			fmt.Println(networkArg, err)
			return
		}

		for _, word := range includeWords {
			if *preFlag {
				if strings.EqualFold(keyPair.public[:len(word)], word) {
					fmt.Printf("%25q included in prefix in public key below\n", word)
					keyPair.Print()
					count++
					break
				}
			}
			if *postFlag {
				if strings.EqualFold(keyPair.public[len(keyPair.public)-len(word):], word) {
					fmt.Printf("%25q included in postfix in public key below\n", word)
					keyPair.Print()
					count++
					break
				}
			}
			if !*preFlag && !*postFlag {
				for i := 0; i < len(keyPair.public)-len(word)+1; i++ {
					if strings.EqualFold(keyPair.public[i:i+len(word)], word) {
						fmt.Printf("%25q included in public key below\n", word)
						keyPair.Print()
						count++
						break
					}
				}
			}
		}
		if count > 10 {
			break
		}
	}
}
