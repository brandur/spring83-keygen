package main

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExpiryDigitsTimeFormat(t *testing.T) {
	testTime := time.Date(2022, 0o7, 11, 1, 1, 1, 1, time.Local)
	require.Equal(t, "0722", testTime.Format(expiryDigitsTimeFormat))
}

func TestFindConformingKey(t *testing.T) {
	ctx := context.Background()

	showKeys := func(key *keyPair, start time.Time, totalIterations int) {
		fmt.Printf("took %v with %d iterations\n", time.Since(start), totalIterations)
		fmt.Printf("private key (hex): %s\n", key.PrivateKeyHex())
		fmt.Printf("public key (hex):  %s\n", key.PublicKeyHex())
	}

	// Ultra simplistic example with no suffix, meaning the first key generated
	// gets returned.
	t.Run("NoSuffix", func(t *testing.T) {
		start := time.Now()
		key, totalIterations, err := findConformingKey(ctx, "")
		require.NoError(t, err)
		require.Equal(t, runtime.NumCPU(), totalIterations)
		showKeys(key, start, totalIterations)
	})

	t.Run("VeryEasySuffix", func(t *testing.T) {
		start := time.Now()
		key, totalIterations, err := findConformingKey(ctx, "aa")
		require.NoError(t, err)
		showKeys(key, start, totalIterations)
	})

	t.Run("EasySuffix", func(t *testing.T) {
		start := time.Now()
		key, totalIterations, err := findConformingKey(ctx, "aaa")
		require.NoError(t, err)
		showKeys(key, start, totalIterations)
	})
}

func TestValidKeySuffix(t *testing.T) {
	testTime := time.Date(2022, 0o7, 11, 1, 1, 1, 1, time.Local)
	require.Equal(t, "83e0724", validKeySuffix(testTime)) // two years in the future
}
