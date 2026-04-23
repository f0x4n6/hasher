package hashes

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

var (
	bib = filepath.Join("..", "testdata", "bible.txt")
	txt = filepath.Join("..", "testdata", "sample.txt")
	jpg = filepath.Join("..", "testdata", "sample.jpg")
)

func TestSum(t *testing.T) {
	for _, tt := range []struct {
		path string
		algo string
		sum  string
	}{
		{txt, ADLER32, "6b0a131c"},
		{jpg, AVERAGE, "fff7e3e3c383c3ff"},
		{txt, BLAKE2S256, "35622f6446178515ba503412f31eb768b092d878acbe6bf422b3ee47cf0558e7"},
		{txt, BLAKE2B256, "adb735516f5c008b29e3313869311096fe671bd2bd5f199b1a49ce579e0f0bd2"},
		{txt, BLAKE2B384, "879b983993f559354807d61b7cdf00c310c093bbb904eb43db9db2b49a83e8a07512d5f24299e458b5374291b23a9f86"},
		{txt, BLAKE2B512, "6805b54f9ad456d6a217624fa0c992108a35cf52f35b9d7f617533b50804bf08b2af20653469b3b76acc799bd3c905919cc958084179adf2b1475493d5cd1810"},
		{txt, BLAKE3256, "68aa491620394f724284e35b51551a21ab715f0c38f85cf8ba837233d34ae4a6"},
		{txt, BLAKE3512, "68aa491620394f724284e35b51551a21ab715f0c38f85cf8ba837233d34ae4a646914037b62a958cc6f769865ea235ae326f8cc4e7eb7010102dfd0d72652d9a"},
		{jpg, BLOCKMEAN, "ffffffffbfff3fff1ffe0ffc1ffc1ffc0fff07f107e007e00fe01fffffffffff"},
		{txt, CRC16CCITT, "3ff9"},
		{txt, CRC32C, "afb3f887"},
		{txt, CRC32IEEE, "7ab53d60"},
		{txt, CRC64ECMA, "df2fc66f2c50575f"},
		{txt, CRC64ISO, "66747f552337d269"},
		{jpg, DIFFERENCE, "08303038f8e8d808"},
		{txt, DJB2, "40f6d9f45fb58b8f"},
		{txt, FLETCHER4, "670c11a5040000007293332e26000000f95ebb7dd7000000cdb2a56cc1030000"},
		{txt, FNV1, "847595167a564758d45f1ac5f7b7fad0"},
		{txt, FNV1A, "8e1fbe2b2d87d680249d1d1135695632"},
		{txt, GOST2012256, "59b14e45039898838d3a905382c73f9d7d73d8a376e770d2c78c744a45de840b"},
		{txt, GOST2012512, "c3893dcdaec9998ac50b551a13f296a5599a1e5443dd508b29fafef6cbe369c063a565a90e0bf7fc0d9367dc59f314684f0dea19d983adf98144f3c107c7b681"},
		{txt, HAS160, "e58d5cfe11171951799249e751e3bafecbf4d4a8"},
		{txt, LSH256, "32be26fe3aab949b3682a6bd77028f9ffe9338fe605a7e7fd45c6a1dfa2c8585"},
		{txt, LSH512, "06d60a9e8abba640bc989578af921ef1e13d333a6d017422fb45fff8611bd8321aaad2b25514877ad4a33ca3b5800f8e349dbf906d97999f9538dbfe0c075dec"},
		{jpg, MARRHILDRETH, "00000000000000000000000000000fe00800000036913afa4aec0000511ce2cff293ec0000103b840e412b5a000000081c0db24926000000000002009c3e00000000000000000000"},
		{txt, MD2, "9e49ada9a2ccafdafffff50137351626"},
		{txt, MD4, "faedf7d245748f2939593258a5e96875"},
		{txt, MD5, "7fe307fda20e805d110b35bcc1f31167"},
		{txt, MD6, "599f033e751832ce908f22a3b0b0bf316a77f1553bc4c24146caf9fa6b235854"},
		{jpg, MEDIAN, "f7e3c1c1818181f3"},
		{txt, MURMUR3, "785ae97135fcdbc8"},
		{jpg, PDQ, "bf00eb007340bf0a392167223666cd8dc4dcf3b818ff18df40f704ff40fd40fe"},
		{jpg, PHASH, "8cc973363966368c"},
		{txt, RAPIDHASH, "10f40b7aad98c3bf"},
		{jpg, RASH, "fe073e000000ffff"},
		{txt, RIPEMD160, "12d7c8698119913bc60a9e1cfeb60853a9015b9d"},
		{txt, SHAKE128, "6a000450724089944184129ff3fa56cd"},
		{txt, SHAKE256, "3988412ad260af82eef7a889f3174147cf652ee07061b3606ea87fa37aabe01c"},
		{txt, SHA1, "b11b92d927f2eb66f0aa17266f7348c0cdfd1105"},
		{txt, SHA224, "03294a8a0ed498f32919abd3e7fda8332db3a99e2c882009056df8ea"},
		{txt, SHA256, "b7e664f9009f84aa056fc78008fe24f33bd45795c407162a78b0fd4c6c2e2d08"},
		{txt, SHA512, "1d34da51ac535e741e1e555bf80a1f4ca784225e1c443ceb6244e624b5548c9892f4b59a9e3776f8843f65b28cde99e9419eb09506feb3c00da9b11e844b58fe"},
		{txt, SHA3, "96c5ca5658d7a04cb844539bcab4c2ebe503bc16c41f79ba207ab011"},
		{txt, SHA3224, "96c5ca5658d7a04cb844539bcab4c2ebe503bc16c41f79ba207ab011"},
		{txt, SHA3256, "40ec86016388c549a4a4954a068989b2b757f6488dce0f1cd4a558ee550129fe"},
		{txt, SHA3384, "66f3c9e7d5c888ada9e8fc37994eb468239a31f2694e4aa8450c7eecf2803d9ef385f6c632b0a9b66452032e29ffefbb"},
		{txt, SHA3512, "794a82f57c8448a5221c8cac462541092f2ef198df3d41edbf5f4ea6f19fdf26f98c37a82eec8be367547822aa5f90e23e2b5f9d26be9f9ee6fb0b654de918e1"},
		{txt, SIPHASH, "013834802422bbba"},
		{txt, SKEIN224, "11d11196404956666a66085a442bc697b7118a10e36de30db25ff7b4"},
		{txt, SKEIN256, "6932c3ecc436c8af84a2ded54657fedcf06e534502e51cee810ba7b4374c5923"},
		{txt, SKEIN384, "5526fcab9893cb9c732f385da9d7e24bb53d232df050b7452aad00402ac98793789b41c7d3044d1f4b8cf704873d2b9e"},
		{txt, SKEIN512, "ff21b1fc0e73509e8cf3d1a5a283ef0acd9b4ecd5e4658dce10e1c1496210e9fbf39889e684629e131d6bca8dcbb789a93ba9f58b36cf06bda96e506708ceca6"},
		{txt, SM3, "c86bb17e03669e27465dbb74c5e8c98035e899414697ab3a31f31345d0ccc2c6"},
		{bib, SSDEEP, "49152:LkD0m3lNkRAA4Ml/Mo3hdWoPPwXj3NfhrZChJl7v6ih7T87/MvwFLSMyJTszqBPh:t"},
		{bib, TLSH, "T12526a757e784133b1b620334620ea5d9f31ac43e7676ce30585ee03e2356c7996b9be8"},
		{txt, WHIRLPOOL, "8aa3c190840f0991205e467f37ba57e8ff0350d10d6a07cd0a54efab6b1a529b97c1f8dd54f6489e55f992855aba3cdb3c8bb60ac072fb89c46dba6cc321dabf"},
		{txt, XXH3, "50b2cde07882a633"},
		{txt, XXH32, "ec6606ef"},
		{txt, XXH64, "d2ff231ddefb0bd0"},
	} {
		t.Run(tt.algo, func(t *testing.T) {
			buf, err := fixture(tt.path)

			if err != nil {
				t.Fatalf("Sum: %v", err)
			}

			sum, err := Sum(tt.algo, buf)

			if err != nil {
				t.Errorf("Sum: %v", err)
			}

			if sum != tt.sum {
				t.Fatal("sum wrong")
			}
		})
	}
}

func BenchmarkSum(b *testing.B) {
	buf, err := fixture(bib)

	if err != nil {
		b.Fatalf("Sum: %v", err)
	}

	for b.Loop() {
		_, _ = Sum(SHA256, buf)
	}
}

func fixture(path string) ([]byte, error) {
	f, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer func() {
		_ = f.Close()
	}()

	b, err := io.ReadAll(f)

	if err != nil {
		return nil, err
	}

	return b, nil
}
