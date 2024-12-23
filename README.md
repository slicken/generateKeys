# generateKeys

**generateKeys** is a simple application that generates self-custodial wallet key pairs for the following blockchains:

- Bitcoin (legacy)
- Bitcoin (BIP39)
- Ethereum
- Solana

## Usage

To run the application, use the following command:


```
me@pc:~$ ./generateKeys
Usage: generateKeys <network> [include]

Generate key pairs for Bitcoin, Ethereum, and Solana.

Arguments:
  <network>    (required) Specifies the blockchain network.
               Options:
                 btc | bitcoin        Bitcoin
                 btc39 | bip39        Bitcoin (BIP39)
                 btcs | segwit        Bitcoin (SegWit)
                 eth | ethereum       Ethereum
                 sol | solana         Solana

  [include]    (optional) A comma-separated list of characters or words
               that the public key should include.
               Example: abcde,10000

```
