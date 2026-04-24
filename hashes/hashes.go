package hashes

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"strings"

	"github.com/cespare/xxhash"
	"github.com/dchest/siphash"
	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"
	"github.com/htruong/go-md2"
	"github.com/jzelinskie/whirlpool"
	"github.com/pedroalbanese/md6"
	"github.com/spaolacci/murmur3"
	"github.com/tjfoc/gmsm/v2/sm3"
	"github.com/zeebo/xxh3"
	"go.dw1.io/rapidhash"
	"go.foxforensics.dev/go-hash/skein"
	"go.foxforensics.dev/go-hash/streebog"
	"go.foxforensics.dev/go-krypto/has160"
	"go.foxforensics.dev/go-krypto/lsh256"
	"go.foxforensics.dev/go-krypto/lsh512"
	"go.foxforensics.dev/hasher/internal/blake3"
	"go.foxforensics.dev/hasher/internal/djb2"
	"go.foxforensics.dev/hasher/internal/image"
	"go.foxforensics.dev/hasher/internal/imports"
	"go.foxforensics.dev/hasher/internal/kermit"
	"go.foxforensics.dev/hasher/internal/lm"
	"go.foxforensics.dev/hasher/internal/nt"
	"go.foxforensics.dev/hasher/internal/pe"
	"go.foxforensics.dev/hasher/internal/shake"
	"go.foxforensics.dev/hasher/internal/xxh"
	"go.solidsystem.no/fletcher4"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
)

const (
	ADLER32      = "adler32"
	AVERAGE      = "average"
	BLAKE2S256   = "blake2s-256"
	BLAKE2B256   = "blake2b-256"
	BLAKE2B384   = "blake2b-384"
	BLAKE2B512   = "blake2b-512"
	BLAKE3256    = "blake3-256"
	BLAKE3512    = "blake3-512"
	BLOCKMEAN    = "blockmean"
	CRC16CCITT   = "crc16-ccitt"
	CRC32C       = "crc32-c"
	CRC32IEEE    = "crc32-ieee"
	CRC64ECMA    = "crc64-ecma"
	CRC64ISO     = "crc64-iso"
	DIFFERENCE   = "difference"
	DJB2         = "djb2"
	FLETCHER4    = "fletcher4"
	FNV1         = "fnv-1"
	FNV1A        = "fnv-1a"
	GOST2012256  = "gost-256"
	GOST2012512  = "gost-512"
	HAS160       = "has-160"
	IMPFUZZY     = "impfuzzy"
	IMPHASH      = "imphash"
	IMPHASH0     = "imphash0"
	LM           = "lm"
	LSH256       = "lsh-256"
	LSH512       = "lsh-512"
	MARRHILDRETH = "marrhildreth"
	MD2          = "md2"
	MD4          = "md4"
	MD5          = "md5"
	MD6          = "md6"
	MEDIAN       = "median"
	MURMUR3      = "murmur3"
	NT           = "nt"
	PDQ          = "pdq"
	PE           = "pe"
	PHASH        = "phash"
	RAPIDHASH    = "rapidhash"
	RASH         = "rash"
	RIPEMD160    = "ripemd-160"
	SHA1         = "sha1"
	SHA224       = "sha224"
	SHA256       = "sha256"
	SHA512       = "sha512"
	SHA3         = "sha3"
	SHA3224      = "sha3-224"
	SHA3256      = "sha3-256"
	SHA3384      = "sha3-384"
	SHA3512      = "sha3-512"
	SHAKE128     = "shake128"
	SHAKE256     = "shake256"
	SIPHASH      = "siphash"
	SKEIN224     = "skein-224"
	SKEIN256     = "skein-256"
	SKEIN384     = "skein-384"
	SKEIN512     = "skein-512"
	SM3          = "sm3"
	SSDEEP       = "ssdeep"
	STREEBOG256  = "streebog-256"
	STREEBOG512  = "streebog-512"
	TLSH         = "tlsh"
	WHASH        = "whash"
	WHIRLPOOL    = "whirlpool"
	XXH3         = "xxh3"
	XXH32        = "xxh32"
	XXH64        = "xxh64"
)

// Algorithms supported
var Algorithms = []string{
	ADLER32,
	AVERAGE,
	BLAKE2S256,
	BLAKE2B256,
	BLAKE2B384,
	BLAKE2B512,
	BLAKE3256,
	BLAKE3512,
	BLOCKMEAN,
	CRC16CCITT,
	CRC32C,
	CRC32IEEE,
	CRC64ECMA,
	CRC64ISO,
	DIFFERENCE,
	DJB2,
	FLETCHER4,
	FNV1,
	FNV1A,
	GOST2012256,
	GOST2012512,
	HAS160,
	IMPFUZZY,
	IMPHASH,
	IMPHASH0,
	LM,
	LSH256,
	LSH512,
	MARRHILDRETH,
	MD2,
	MD4,
	MD5,
	MD6,
	MEDIAN,
	MURMUR3,
	NT,
	PDQ,
	PE,
	PHASH,
	RAPIDHASH,
	RASH,
	RIPEMD160,
	SHAKE128,
	SHAKE256,
	SHA1,
	SHA256,
	SHA512,
	SHA3,
	SHA3224,
	SHA3256,
	SHA3384,
	SHA3512,
	SIPHASH,
	SKEIN224,
	SKEIN256,
	SKEIN384,
	SKEIN512,
	SM3,
	SSDEEP,
	STREEBOG256,
	STREEBOG512,
	TLSH,
	WHASH,
	WHIRLPOOL,
	XXH3,
	XXH32,
	XXH64,
}

// ErrAlgorithmNotSupported for unknown algorithms
var ErrAlgorithmNotSupported = errors.New("algorithm not supported")

// Sum returns the hash sum of the given data using the given algorithm.
func Sum(algo string, data []byte) (string, error) {
	var imp hash.Hash

	ssdeep.Force = true

	switch strings.ToLower(algo) {
	case ADLER32:
		imp = adler32.New()
	case AVERAGE:
		imp = image.New(image.Average)
	case BLAKE2B256:
		imp, _ = blake2b.New256(nil)
	case BLAKE2B384:
		imp, _ = blake2b.New384(nil)
	case BLAKE2B512:
		imp, _ = blake2b.New512(nil)
	case BLAKE2S256:
		imp, _ = blake2s.New256(nil)
	case BLAKE3256:
		imp = blake3.New256()
	case BLAKE3512:
		imp = blake3.New512()
	case BLOCKMEAN:
		imp = image.New(image.BlockMean)
	case CRC16CCITT:
		imp = kermit.New()
	case CRC32C:
		imp = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case CRC32IEEE:
		imp = crc32.NewIEEE()
	case CRC64ECMA:
		imp = crc64.New(crc64.MakeTable(crc64.ECMA))
	case CRC64ISO:
		imp = crc64.New(crc64.MakeTable(crc64.ISO))
	case DIFFERENCE:
		imp = image.New(image.Difference)
	case DJB2:
		imp = djb2.New()
	case FLETCHER4:
		imp = fletcher4.New()
	case FNV1:
		imp = fnv.New128()
	case FNV1A:
		imp = fnv.New128a()
	case GOST2012256, STREEBOG256:
		imp = streebog.New256()
	case GOST2012512, STREEBOG512:
		imp = streebog.New512()
	case HAS160:
		imp = has160.New()
	case IMPFUZZY:
		imp = imports.New()
	case IMPHASH:
		imp = imports.New()
	case IMPHASH0:
		imp = imports.NewStable()
	case LM:
		imp = lm.New()
	case LSH256:
		imp = lsh256.New()
	case LSH512:
		imp = lsh512.New()
	case MARRHILDRETH:
		imp = image.New(image.MarrHildreth)
	case MD2:
		imp = md2.New()
	case MD4:
		imp = md4.New()
	case MD5:
		imp = md5.New()
	case MD6:
		imp = md6.New256()
	case MEDIAN:
		imp = image.New(image.Median)
	case MURMUR3:
		imp = murmur3.New64() // Murmur3f
	case NT:
		imp = nt.New()
	case PDQ:
		imp = image.New(image.PDQ)
	case PE:
		imp = pe.New()
	case PHASH:
		imp = image.New(image.PHash)
	case RAPIDHASH:
		imp = rapidhash.New()
	case RASH:
		imp = image.New(image.RASH)
	case RIPEMD160:
		imp = ripemd160.New()
	case SHA1:
		imp = sha1.New()
	case SHA224:
		imp = sha256.New224()
	case SHA256:
		imp = sha256.New()
	case SHA512:
		imp = sha512.New()
	case SHA3:
		fallthrough
	case SHA3224:
		imp = sha3.New224()
	case SHA3256:
		imp = sha3.New256()
	case SHA3384:
		imp = sha3.New384()
	case SHA3512:
		imp = sha3.New512()
	case SHAKE128:
		imp = shake.New128()
	case SHAKE256:
		imp = shake.New256()
	case SIPHASH:
		imp = siphash.New(make([]byte, 16)) // SipHash-2-4 with zero key
	case SKEIN224:
		imp = skein.NewHash224()
	case SKEIN256:
		imp = skein.NewHash256()
	case SKEIN384:
		imp = skein.NewHash384()
	case SKEIN512:
		imp = skein.NewHash512()
	case SM3:
		imp = sm3.New()
	case SSDEEP:
		imp = ssdeep.New()
	case TLSH:
		imp = tlsh.New()
	case WHASH:
		imp = image.New(image.WHash)
	case WHIRLPOOL:
		imp = whirlpool.New()
	case XXH3:
		imp = xxh3.New()
	case XXH32:
		imp = xxh.New()
	case XXH64:
		imp = xxhash.New()
	default:
		return "", ErrAlgorithmNotSupported
	}

	imp.Reset()

	if _, err := imp.Write(data); err != nil {
		return "", err
	}

	switch algo {
	case SSDEEP, IMPFUZZY:
		return fmt.Sprintf("%s", imp.Sum(nil)), nil
	case TLSH:
		return fmt.Sprintf("T1%x", imp.Sum(nil)), nil
	default:
		return fmt.Sprintf("%x", imp.Sum(nil)), nil
	}
}
