package main

import (
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

// Print to std.out
func (k KeyPair) Print() {
	fmt.Printf("%-3s %-12s %s\n", k.network, "public", k.public)
	fmt.Printf("%-3s %-12s %s\n", k.network, "private", k.private)
	if k.mnemonic != "" {
		fmt.Printf("%-3s %-12s %s\n", k.network, "mnemonic", k.mnemonic)
	}
	if k.derivationPath != "" {
		fmt.Printf("%-3s %-12s %s\n", k.network, "derivation", k.derivationPath)
	}
}

type Network interface {
	Name() string
	GenerateKeys() (*KeyPair, error)
}

func Split(s string) []string {
	var slice []string
	return append(slice, strings.Split(s, ",")...)
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("GENERATE KEYS")
		fmt.Println("Usage:", os.Args[0], "[btc, bip39, eth, sol] (xoxo,or,other,to,must,include,in,public)")
		return
	}

	var coin Network
	switch strings.ToLower(os.Args[1]) {
	case "btc", "bitcoin":
		coin = network["btc"]
	case "btc39", "bip39":
		coin = network["bip39"]
	case "eth", "ethereum":
		coin = &ethereum{}
	case "sol", "solana":
		coin = &solana{}
	default:
		log.Fatalf("%q not found\n", os.Args[1])
	}

	// fmt.Printf("%s\n%v\n", coin.Info(), coin.Info())
	// os.Exit(0)

	// If we just want to generate a keypair
	if len(os.Args) == 2 {
		if os.Args[1] != "btc" && os.Args[1] != "bitcoin" && os.Args[1] != "btc39" && os.Args[1] != "bip39" &&
			os.Args[1] != "eth" && os.Args[1] != "ethereum" && os.Args[1] != "sol" && os.Args[1] != "solana" {
			fmt.Println("GENERATE KEYS")
			fmt.Println("Usage:", os.Args[0], "[btc, bip39, eth, sol] (xoxo,or,other,to,must,include,in,public)")
			return
		}

		keyPair, err := coin.GenerateKeys()
		if err != nil {
			log.Fatalln(os.Args[1], err)
		}
		keyPair.Print()
		return
	}

	// Add logic for "include" command here
	if len(os.Args) < 3 {
		fmt.Println("GENERATE KEYS")
		fmt.Println("Usage:", os.Args[0], "[btc, bip39, eth, sol] (xoxo,or,other,to,must,include,in,public)")
		return
	}

	wordlist := Split(os.Args[2])
	if len(wordlist) == 0 {
		log.Fatalln("no words to include")
	}

	fmt.Printf("> generating %s keys that includes %s\n", os.Args[1], wordlist)

	for {
		keyPair, err := coin.GenerateKeys()
		if err != nil {
			fmt.Println(os.Args[1], err)
			return
		}

		for _, word := range wordlist {
			for i := 0; i < len(keyPair.public); i++ {
				if keyPair.public[i] == word[0] {
					match := true
					for j := 1; j < len(word); j++ {
						if i+j >= len(keyPair.public) || strings.ToLower(string(keyPair.public[i+j])) != string(word[j]) {
							match = false
							break
						}
					}
					if match {
						fmt.Printf("%25q included in public key below\n", word)
						keyPair.Print()
					}
				}
			}
		}
	}
}
