# generateKeys

**generateKeys** is a simple application that generates self-custodial wallet key pairs for the following blockchains:

- Bitcoin (legacy)
- Bitcoin (BIP39)
- Ethereum
- Solana

## Usage

To run the application, use the following command:

```bash
me@pc:~$ ./generateKeys
GENERATE KEY PAIRS for Bitcoin, Ethereum, and Solana
Usage: ./app <network> [include]

Arguments:
  <network>    (required) Specifies the blockchain network.
               Options:
                 btc, bitcoin
                 btc39, bip39
                 eth, ethereum
                 sol, solana

  [include]    (optional) A comma-separated list of characters or words that the public key should include.
               Example: abcde,10000
```
