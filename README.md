sha256-sat -- SAT instance generator for SHA-256
================================================


# Compiling (UNIX)

To compile, you first need to make sure you have the Boost libraries
installed. When you do, simply run make.sh (default espresso not enabled):

> bash make.sh

Have a look into make.sh how to enable espresso,
by added "-DENABLE_HALFADDER_VIA_ESPRESSO=1" to compile options.

# Compiling (Windows)

To compile, you first need to make sure you have the Boost libraries
installed. It also assumes you have MinGW64 installed.
When you do, simply run:

> g++ -I. -std=c++0x -Wsign-compare -Wtype-limits -Wuninitialized -Wno-deprecated \
  -O2 -ggdb -Id:\boost_1_53_0 main.cc \
  d:\boost_1_53_0\lib\x64mingw\lib\libboost_program_options-mgw47-mt-s-1_53.a \
  -o main.exe

# Running (Unix)

With Unix you can select if you want to use espresso or not.
There is a command line option for the compiler "-DENABLE_HALFADDER_VIA_ESPRESSO=1"
to enable espresso. If you don't want to use espresso, just let it away.
Before running, please make sure that the espresso binary is in your PATH.
espresso is used to minimise the truth tables for the pseudo-boolean
constraints used to encode the adders. You can obtain espresso from
<ftp://ftp.cs.man.ac.uk/pub/amulet/balsa/other-software/espresso-ab-1.0.tar.gz>.

> wget ftp://ftp.cs.man.ac.uk/pub/amulet/balsa/other-software/espresso-ab-1.0.tar.gz
> tar xzvf espresso-ab-1.0.tar.gz
> cd espresso-ab-1.0
> ./configure
> make
> cd ..
> export PATH="$PWD/espresso-ab-1.0/src:$PATH"

To generate a CNF instance encoding a preimage attack on the full SHA-1
algorithm, run:

> ./main --cnf --tseitin-adders --hash-bits=256 > sha256_tseitin_adders.cnf
> ./main --cnf                  --hash-bits=256 > sha256_espresso.cnf

Attention:
Beginning of CNF file contains setting of message,
please cut away, if you want to set general messages.
(Will be correct in a future release)

To look at the possible options, run:

> ./main --help

Attention: Not yet completely up-to-date or checked if correct!

The program can also generate OPB instances (pseudo-boolean constraints) if
you specify --opb instead of --cnf.

Attention: OPB not checked!

# Verifying solutions (Unix)

Attention: Not checked!

To verify that the solution output by the solver is actually correct, run:

> perl verify-preimage instance.cnf solution | ./verify-preimage

Here, 'solution' is the file output e.g. by minisat or the 'v'-line for
other popular solvers like CryptoMiniSAT or PrecoSAT. The program returns
an error code of 0 if and only if the solution is correct.

# Description of CNF files

Generated CNF files contain helpful comment, please have a look into files.

This program can generate two variants: SHA256 and Bitcoin
Bitcoin uses two rounds of SHA256, feeding the result of the first round
into the message part of the second round.
First test were done with two separate rounds, one for each round of SHA256 of Bitcoin.

- sha256_tseitin_adders_without_message_nor_hash.cnf
  This is CNF for general SHA256 created with TSEITIN ADDERS
  (./main --cnf --tseitin-adders --hash-bits=256 > sha256_tseitin_adders.cnf
   and cut away setting of message bits)

- sha256_espresso_without_message_nor_hash.cnf
  This is CNF for general SHA256 created with TSEITIN ADDERS
  (./main --cnf --hash-bits=256 > sha256_espresso.cnf
   and cut away setting of message bits)

- set_sha256_message_hello.cnf
  Sets "hello" into w[0] to w[15] (which is located from 1 to 512)

- set_sha256_message_5_bytes_long.cnf
  Contain content which sets message length to 5 bytes,
  these first 5 bytes (w[0] and one byte in w[1]) are freely available,
  all other bytes are set to 0x00, length set to 40 bits.
  w[0] to w[15] are located from 1 to 512.

- set_sha256_bitcoin_second_round_half_message_fixed.cnf
  Contain content which sets message length to 32 bytes,
  these first 32 bytes (w[0] to w[7]) are freely available,
  all other bytes are set to 0x00, length set to 256 bits
  w[0] to w[15] are located from 1 to 512.
  This is used for Bitcoin where resulting hash (256 bits)
  is set into message for second round.

- set_sha256_bitcoin_second_round_half_message_hash_of_hello.cnf
  This file contains the result of SHA256("hello") as
  content for the first 256 bits of the message.

- set_sha256_bitcoin_second_round_half_message_hash_of_hello_reduced_to_248_bits.cnf
  This file contains the result of SHA256("hello") as
  content for the first 256 bits of the message,
  but reduced to first 248 bits.

- set_sha256_bitcoin_second_round_half_message_hash_of_hello_reduced_to_240_bits.cnf
  This file contains the result of SHA256("hello") as
  content for the first 256 bits of the message,
  but reduced to first 240 bits.

- set_sha256_bitcoin_second_round_half_message_hash_of_hello_reduced_to_236_bits.cnf
  This file contains the result of SHA256("hello") as
  content for the first 256 bits of the message,
  but reduced to first 236 bits.

- set_sha256_bitcoin_second_round_hash_of_hello.cnf
- set_sha256_hash_of_message_hello.cnf

bitcoin_tseitin_adders.cnf
- set_bitcoin_hash_of_message_hello.cnf


Examples with Cryptominisat (64 Bit):

cryptominisat64.exe --input=set_sha256_message_5_bytes_long.cnf
                    --input=set_bitcoin_hash_of_message_hello.cnf
                    --input=bitcoin_irred_9.cnf
                    --dumpres=bitcoin_test.res

# About

This program is based on work of Vegard Nossum <vegard.nossum@gmail.com>.
CHanges for SHA-256 were done by Martin Maurer <Martin.Maurer@clibb.de>.
