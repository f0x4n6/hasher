// Multi-algorithm hasher supporting cryptographic, performance and perceptual hashes, as well as different checksums.
//
// Usage:
//
//	hasher algo path
//
// The arguments are:
//
//	algo
//		    Hash algorithm to used (required).
//	path
//		    File or folder to hash (required).
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.foxforensics.dev/go-mmap"
	"go.foxforensics.dev/hasher/hashes"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] == "--help" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: hasher algo path")

		for _, algo := range hashes.Algorithms {
			_, _ = fmt.Fprintln(os.Stderr, algo)
		}

		os.Exit(2)
	}

	err := filepath.WalkDir(os.Args[2], func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			return nil
		}

		if d.IsDir() {
			return nil
		}

		path, err = filepath.Abs(path)

		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			return nil
		}

		f, err := os.Open(path)

		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			return nil
		}

		defer func() { _ = f.Close() }()

		m, err := mmap.Map(f, mmap.RDONLY, 0)

		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			return nil
		}

		defer func() { _ = m.Unmap() }()

		s, err := hashes.Sum(os.Args[1], m)

		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			return nil
		}

		_, _ = fmt.Printf("%s  %s\n", s, path)
		return nil
	})

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
