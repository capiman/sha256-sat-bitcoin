sha256-sat-bitcoin -- SAT instance generator for SHA-256 and BITCOIN
====================================================================

# Compiling (UNIX)

To compile, you first need to make sure you have the Boost libraries
installed. When you do, simply run make.sh (default espresso not enabled):

```
> bash make.sh
```

Have a look into make.sh how to enable espresso,
by added "-DENABLE_HALFADDER_VIA_ESPRESSO=1" to compile options.

# Compiling (Windows)

To compile, you first need to make sure you have the Boost libraries
installed. It also assumes you have MinGW64 installed.
When you do, simply run:

```
g++ -I. -std=c++0x -Wsign-compare -Wtype-limits -Wuninitialized -Wno-deprecated \
  -O2 -ggdb -Id:\boost_1_53_0 main.cc \
  d:\boost_1_53_0\lib\x64mingw\lib\libboost_program_options-mgw47-mt-s-1_53.a \
  -o main.exe
```

# Running (Unix)

With Unix you can select if you want to use espresso or not.
There is a command line option for the compiler "-DENABLE_HALFADDER_VIA_ESPRESSO=1"
to enable espresso. If you don't want to use espresso, just let it away.
Before running, please make sure that the espresso binary is in your PATH.
espresso is used to minimise the truth tables for the pseudo-boolean
constraints used to encode the adders. You can obtain espresso from
<ftp://ftp.cs.man.ac.uk/pub/amulet/balsa/other-software/espresso-ab-1.0.tar.gz>.

```
> wget ftp://ftp.cs.man.ac.uk/pub/amulet/balsa/other-software/espresso-ab-1.0.tar.gz
> tar xzvf espresso-ab-1.0.tar.gz
> cd espresso-ab-1.0
> ./configure
> make
> cd ..
> export PATH="$PWD/espresso-ab-1.0/src:$PATH"
```

To generate a CNF instance encoding a preimage attack on the full SHA-1
algorithm, run:

```
> ./main --cnf --tseitin-adders --hash-bits=256                  > sha256_tseitin_adders.cnf
> ./main --cnf                  --hash-bits=256                  > sha256_espresso.cnf
> ./main --cnf --tseitin-adders --hash-bits=256 --attack=bitcoin > bitcoin_tseitin_adders.cnf
> ./main --cnf                  --hash-bits=256 --attack=bitcoin > bitcoin_espresso.cnf
```

Attention:
Beginning of CNF file contains setting of message,
please cut away, if you want to set general messages.
(Will be correct in a future release)

Attention: A lot of command line option are not supported yet,
even when they are already available and can be called.

To look at the possible options, run:

```
> ./main --help
```

Attention: Not yet completely up-to-date or checked if correct!

The program can also generate OPB instances (pseudo-boolean constraints) if
you specify --opb instead of --cnf.

Attention: OPB not checked!

# Verifying solutions (Unix)

Attention: Not checked!

To verify that the solution output by the solver is actually correct, run:

```
> perl verify-preimage instance.cnf solution | ./verify-preimage
```

Here, 'solution' is the file output e.g. by minisat or the 'v'-line for
other popular solvers like CryptoMiniSAT or PrecoSAT. The program returns
an error code of 0 if and only if the solution is correct.

# Description of CNF files

Generated CNF are gzipped to save space on github.
Generated CNF files contain helpful comment,
please decompress them and have a look into the files.

Example (from bitcoin_tseitin_adders.cnf, grep for "c var"):
```
c var 1/32 wr0[0] -> this is input message, each entry 32 bits
c var 33/32 wr0[1]
c var 65/32 wr0[2]
c var 97/32 wr0[3]
c var 129/32 wr0[4]
c var 161/32 wr0[5]
c var 193/32 wr0[6]
c var 225/32 wr0[7]
c var 257/32 wr0[8]
c var 289/32 wr0[9]
c var 321/32 wr0[10]
c var 353/32 wr0[11]
c var 385/32 wr0[12]
c var 417/32 wr0[13]
c var 449/32 wr0[14]
c var 481/32 wr0[15]
...
c var 2049/32 hr0_out0 -> this is hash output, after first round of SHA256 (round 0)
c var 2081/32 hr0_out1
c var 2113/32 hr0_out2
c var 2145/32 hr0_out3
c var 2177/32 hr0_out4
c var 2209/32 hr0_out5
c var 2241/32 hr0_out6
c var 2273/32 hr0_out7
...
c var 132258/32 hr1_out0 -> this is final hash output, after second round of SHA256 (round 1)
c var 132290/32 hr1_out1
c var 132322/32 hr1_out2
c var 132354/32 hr1_out3
c var 132386/32 hr1_out4
c var 132418/32 hr1_out5
c var 132450/32 hr1_out6
c var 132482/32 hr1_out7
```

Pay attention that numbers which represent variables can change
when internal calculation is changed.
(can perhaps be fixed in future by putting "global" variables
in front of "local" variables)

All files start with "set" set certain variables,
likes setting the message, the hash, intermediate results
or at least parts of them. No complete calculation!

This program can generate two variants: SHA256 and Bitcoin
Bitcoin uses two rounds of SHA256, feeding the result of the first round
into the message part of the second round.
First test were done with two separate rounds, one for each round of SHA256 of Bitcoin.

All the example are based on the example, which is mentioned on a bitcoin Wiki:

https://en.bitcoin.it/wiki/Protocol_specification

```
Message "hello"
Hash    2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 (hash, result of first round of sha-256)
Hash    9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50 (hash, result of second round of sha-256)
```

Single round CNFs:
(file names start with sha256 or set_sha256)

- sha256_tseitin_adders_without_message_nor_hash.cnf

```
  This is CNF for general SHA256 created with TSEITIN ADDERS

  (./main --cnf --tseitin-adders --hash-bits=256 > sha256_tseitin_adders.cnf

   and cut away setting of message bits)
```

- sha256_espresso_without_message_nor_hash.cnf

```
  This is CNF for general SHA256 created with TSEITIN ADDERS

  (./main --cnf --hash-bits=256 > sha256_espresso.cnf

   and cut away setting of message bits)
```

- set_sha256_message_hello.cnf

```
  Sets "hello" into w[0] to w[15] (which is located from 1 to 512)
```

- set_sha256_message_5_bytes_long.cnf

```
  Contain content which sets message length to 5 bytes,
  these first 5 bytes (w[0] and one byte in w[1]) are freely available,
  all other bytes are set to 0x00, length set to 40 bits.
  w[0] to w[15] are located from 1 to 512.
```

- set_sha256_bitcoin_second_round_half_message_fixed.cnf

```
  Contain content which sets message length to 32 bytes,
  these first 32 bytes (w[0] to w[7]) are freely available,
  all other bytes are set to 0x00, length set to 256 bits
  w[0] to w[15] are located from 1 to 512.
  This is used for Bitcoin where resulting hash (256 bits)
  is set into message for second round.
```

- set_sha256_bitcoin_second_round_half_message_hash_of_hello.cnf

```
  This file contains the result of SHA256("hello") as
  content for the first 256 bits of the message.
```

- set_sha256_bitcoin_second_round_half_message_hash_of_hello_reduced_to_248_bits.cnf

```
  This file contains the result of SHA256("hello") as
  content for the first 256 bits of the message,
  but reduced to first 248 bits.
```

- set_sha256_bitcoin_second_round_half_message_hash_of_hello_reduced_to_240_bits.cnf

```
  This file contains the result of SHA256("hello") as
  content for the first 256 bits of the message,
  but reduced to first 240 bits.
```

- set_sha256_bitcoin_second_round_half_message_hash_of_hello_reduced_to_236_bits.cnf

```
  This file contains the result of SHA256("hello") as
  content for the first 256 bits of the message,
  but reduced to first 236 bits.
```

- set_sha256_bitcoin_second_round_hash_of_hello.cnf

```
  Variables 2049 to 2304
  This is the hash for hello of two rounds (=SHA256(SHA256(x))),
  which means it calculates the second half of a bitcoin calculation.
```

- set_sha256_hash_of_message_hello.cnf

```
  Variables 2049 to 2304
  This is the hash for hello of one rounds (=SHA256(x)),
  which means it calculates the first half of a bitcoin calculation.
```

Double round CNFs:
(file names start with bitcoin or set_bitcoin)

- bitcoin_tseitin_adders.cnf

```
  This file contains 2 sequential rounds of SHA256 to do the same as bitcoin.
```

- set_bitcoin_hash_of_message_hello.cnf

```
  Hash of message hello for bitcoin (2 rounds) with tseitsin adders
```

Examples with Cryptominisat and SHA256:

To verify it is working in general:

```
cryptominisat --input=set_sha256_message_hello.cnf
              --input=sha256_tseitin_adders_without_message_nor_hash.cnf
              --dumpres=sha256_test.res

type sha256_test.res | sha256dbg | more
```

Examples with Cryptominisat and Bitcoin CNF:

To verify it is working in general:

```
cryptominisat --input=set_sha256_message_hello.cnf
              --input=bitcoin_tseitin_adders.cnf
              --dumpres=bitcoin_test.res

type bitcoin_test.res | bitcoindbg | more
```

To check if there is a 5 byte long message which has hash of "hello":
(takes endless, but has at least one solution for "hello")

```
cryptominisat --input=set_sha256_message_5_bytes_long.cnf
              --input=set_bitcoin_hash_of_message_hello.cnf
              --input=bitcoin_tseitin_adders.cnf
              --dumpres=bitcoin_test.res
```

# Comments

All in all it takes too long to do useful things with it...

In my tests with CMS 3.x the version with TSEITIN ADDERS
were faster than version with ESPRESSO.

I used ESPRESSO only on a Raspberry PI to generate the files,
not used them much on my PC afterwards.

# About

This program is based on work of Vegard Nossum <vegard.nossum@gmail.com>.

Changes for SHA-256 were done by Martin Maurer <Martin.Maurer@clibb.de>.

If you use the program in your research,
please make a note of this in your acknowledgements and let us know about your paper/thesis/etc.!

If you find this implementation helpful and/or want to donate:

bitcoin:  17PWCG8HwNhJic1GcCdPdisgGni6S2is6X

dogecoin: DLpXoHiv8nWQrbnrJLrdzW9e4w1rhqN3y3
