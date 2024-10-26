# generateKeys
Simple app that generates self costodial wallet key pairs for Bitcoin (legacy), Bitcoin (BIP39), Ethereum, Solana<br>
```
me@pc:~$ ./generateKeys 
GENERATE KEYS
Usage: ./generateKeys [btc, bip39, eth, sol] (xoxo,or,other,to,must,include,in,public)
```
if you want generate ublic keys with specific word in it, you can.
Example:
```
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
