package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
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

type keyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func (p *keyPair) PrivateKeyHex() string { return hex.EncodeToString(p.PrivateKey) }
func (p *keyPair) PublicKeyHex() string  { return hex.EncodeToString(p.PublicKey) }

func main() {
	var (
		t            = time.Now()
		targetSuffix = validKeySuffix(t)
	)

	key, err := findConformingKey(context.Background(), targetSuffix)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("spring '83 key successfully brute forced in %v\n", time.Since(t))
	fmt.Printf("private key (hex): %s\n", key.PrivateKeyHex())
	fmt.Printf("public key (hex):  %s\n", key.PublicKeyHex())
}

func findConformingKey(ctx context.Context, targetSuffix string) (*keyPair, error) {
	var (
		closeChan        = make(chan struct{})
		conformingKey    *keyPair
		conformingKeyMut sync.Mutex
	)

	{
		errGroup, _ := errgroup.WithContext(ctx)

		for i := 0; i < runtime.NumCPU(); i++ {
			errGroup.Go(func() error {
				for {
					// Check if we're done by looking for a close on the close
					// channel.
					select {
					case <-closeChan:
						return nil
					default:
					}

					publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						return xerrors.Errorf("error generating key: %w", err)
					}

					key := &keyPair{privateKey, publicKey}

					if strings.HasSuffix(key.PublicKeyHex(), targetSuffix) {
						conformingKeyMut.Lock()
						conformingKey = key
						conformingKeyMut.Unlock()

						// Wrapped in a select to ensure that only one goroutine
						// ends up closing the channel.
						select {
						case <-closeChan:
						default:
							close(closeChan)
						}
					}
				}
			})
		}

		if err := errGroup.Wait(); err != nil {
			return nil, xerrors.Errorf("error finding key: %w", err)
		}
	}

	return conformingKey, nil
}

func validKeySuffix(t time.Time) string {
	return "83e" + t.Add(validKeyAge).Format(expiryDigitsTimeFormat)
}
