# generateKeys

**generateKeys** is a simple application that generates self-custodial wallet key pairs for the following blockchains:

- Bitcoin (legacy)
- Bitcoin (SegWit)
- Bitcoin (Native SegWit)
- Bitcoin (Taproot) !! not implemented yet !!
- Ethereum
- Solana

## Usage

To run the application, use the following command:

```
me@pc:~$ ./generateKeys
Usage: generateKeys <NETWORK> [OPTION]

Generate key pairs for Bitcoin, Ethereum, and Solana.

Network (required):
  btc, legacy              Legacy (P2PKH): Oldest type, less efficient, higher fees.
  btcs, segwit             SegWit (P2SH-wrapped P2WPKH): SegWit compatibility, lower fees.
  btcn, native             Native SegWit (P2WPKH, Bech32): More efficient and secure, lower fees.
  eth, ethereum            Ethereum.
  sol, solana              Solana.

Option:
  -m, --mnemonic           Prints mnemonic for the wallet.
  -i, --include <include>  Include words in public key (comma-separated).
      --prefix             Addon for include.
      --postfix            Addon for include.
                           Example: generateKeys btcn -i abcde,10000 --postfix
  -h, --help               Show this help message.
```
