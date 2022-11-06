package main

import (
	"context"
	"fmt"
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

	showKeys := func(key *keyPair) {
		fmt.Printf("private key (hex): %s\n", key.PrivateKeyHex())
		fmt.Printf("public key (hex):  %s\n", key.PublicKeyHex())
	}

	// Ultra simplistic example with no suffix, meaning the first key generated
	// gets returned.
	t.Run("NoSuffix", func(t *testing.T) {
		key, err := findConformingKey(ctx, "")
		require.NoError(t, err)
		showKeys(key)
	})

	t.Run("VeryEasySuffix", func(t *testing.T) {
		key, err := findConformingKey(ctx, "aa")
		require.NoError(t, err)
		showKeys(key)
	})

	t.Run("EasySuffix", func(t *testing.T) {
		key, err := findConformingKey(ctx, "aaa")
		require.NoError(t, err)
		showKeys(key)
	})
}

func TestValidKeySuffix(t *testing.T) {
	testTime := time.Date(2022, 0o7, 11, 1, 1, 1, 1, time.Local)
	require.Equal(t, "83e0724", validKeySuffix(testTime)) // two years in the future
}
