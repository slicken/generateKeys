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
me@pc:~$ ./generateKeys eth abcde,10000
> generating eth keys that includes [abcde 10000]
                  "abcde" included in public key below
ethereum public       0x505014aeabcde25b12be069cfdc0e12890167226
ethereum private      8468830dd9ed38b5114b80410fcca96435b870fdd2e3fb52c959db82bbe4e67c
                  "abcde" included in public key below
ethereum public       0x2aa2bdda9abcdeb640a781140fd06b7099feff83
ethereum private      577c58185848c909e07f0fef4b39b193b7c03c136a7ecdea81a7065f94308685
                  "10000" included in public key below
ethereum public       0x1a116803fe78765100000f482d1d1a2432c91daa
ethereum private      52bd3ae219ba360822cd889598be8353a35b46380ed956d8b6dad93fcec42424
```
test
