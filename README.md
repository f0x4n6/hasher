# hasher
Multi-algorithm hasher supporting cryptographic, performance and perceptual hashes, as well as different checksums.

```console
go install go.foxforensics.dev/hasher@latest
```

## Usage
```console
$ hasher ALGO PATH
```

## Algorithms
> Adler32
Average
BLAKE2s-256
BLAKE2b-256
BLAKE2b-384
BLAKE2b-512
BLAKE3-256
BLAKE3-512
Blockmean
CRC16-CCITT
CRC32-C
CRC32-IEEE
CRC64-ECMA
CRC64-ISO
Difference
Djb2
Fletcher4
FNV-1
FNV-1a
GOST-256
GOST-512
HAS-160
LSH-256
LSH-512
marrhildreth
MD2
MD4
MD5
MD6
Median
Murmur3
PDQ
phash
Rapidhash
rash
RIPEMD-160
shake128
shake256
SHA1
SHA256
SHA512
SHA3
SHA3-224
SHA3-256
SHA3-384
SHA3-512
Siphash
Skein-224
Skein-256
Skein-384
Skein-512
SM3
SSDeep
Streebog-256
Streebog-512
TLSH
whash
Whirlpool
XXH3
XXH32
XXH64

## License
Released under the [MIT License](LICENSE.md).