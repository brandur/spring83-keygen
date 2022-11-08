package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

const (
	// Month/year digits encoded into the end of a Spring '83 public key.
	expiryDigitsTimeFormat = "0106"

	// Spring '83 keys have a maximum expiry age of two years.
	validKeyAge = 2 * 365 * 24 * time.Hour
)

type ed25519KeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func (p *ed25519KeyPair) PrivateKeyHex() string { return hex.EncodeToString(p.PrivateKey) }
func (p *ed25519KeyPair) PublicKeyHex() string  { return hex.EncodeToString(p.PublicKey) }

func main() {
	t := time.Now()
	targetSuffix := validKeySuffix(t)

	fmt.Printf("Brute forcing a Spring '83 key (this could take a while)\n")

	key, totalIterations, err := findConformingKey(context.Background(), targetSuffix)
	if err != nil {
		abort(err.Error())
	}

	fmt.Printf("Succeeded in %v with %d iterations\n", time.Since(t), totalIterations)
	fmt.Printf("Private key (hex): %s\n", key.PrivateKeyHex())
	fmt.Printf("Public  key (hex): %s\n", key.PublicKeyHex())
}

func abort(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}

// Runs a parallel search for an Ed25519 key where the hex-encoded public
// portion has the given target suffix.
func findConformingKey(ctx context.Context, targetSuffix string) (*ed25519KeyPair, int, error) {
	var (
		conformingKeyChan = make(chan *ed25519KeyPair, runtime.NumCPU())
		done              atomic.Bool
		totalIterations   int64
	)

	targetSuffixBytes, oddChars := hexBytes(targetSuffix)

	{
		errGroup, _ := errgroup.WithContext(ctx)

		for i := 0; i < runtime.NumCPU(); i++ {
			errGroup.Go(func() error {
				for numIterations := 0; ; numIterations++ {
					if done.Load() {
						atomic.AddInt64(&totalIterations, int64(numIterations))
						return nil
					}

					publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						return xerrors.Errorf("error generating key: %w", err)
					}

					if !suffixBytesEqual([]byte(privateKey), targetSuffixBytes, oddChars) {
						continue
					}

					conformingKeyChan <- &ed25519KeyPair{privateKey, publicKey}

					done.Store(true)
				}
			})
		}

		if err := errGroup.Wait(); err != nil {
			return nil, 0, xerrors.Errorf("error finding key: %w", err)
		}
	}

	return <-conformingKeyChan, int(totalIterations), nil
}

// Breaks the given hex string into bytes. The boolean flag indicates whether
// there was an odd number of hex characters which means that the most
// significant byte only represents half a byte worth of relevant information.
func hexBytes(s string) ([]byte, bool) {
	var oddChars bool
	if len(s)%2 == 1 {
		oddChars = true
		s = "0" + s
	}

	sBytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return sBytes, oddChars
}

// Bytewise suffix comparison that lets us avoid encoding every single generated
// key to a hex string. The `oddChars` flag handles the case where we only care
// about the half byte at the boundary, as is the case with a Spring '83 key
// where the last seven hex characters are relevant (each two characters are a
// byte).
func suffixBytesEqual(b, suffix []byte, oddChars bool) bool {
	if len(suffix) < 1 {
		return true
	}

	if oddChars {
		bBoundary := b[len(b)-len(suffix)]
		suffixBoundary := suffix[0]

		// Compare the half byte at the boundary, and then the rest of suffix
		// bytes as usual.
		return bBoundary&0x0f == suffixBoundary&0x0f &&
			bytes.Equal(b[len(b)-len(suffix)+1:], suffix[1:])
	}

	return bytes.Equal(b[len(b)-len(suffix):], suffix)
}

func validKeySuffix(t time.Time) string {
	return "83e" + t.Add(validKeyAge).Format(expiryDigitsTimeFormat)
}
