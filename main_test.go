package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
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
		require.LessOrEqual(t, totalIterations, runtime.NumCPU())
		showKeys(key, start, totalIterations)
	})

	t.Run("VeryEasySuffix", func(t *testing.T) {
		start := time.Now()
		key, totalIterations, err := findConformingKey(ctx, "aa")
		require.NoError(t, err)
		require.True(t, strings.HasSuffix(key.PublicKeyHex(), "aa"))
		showKeys(key, start, totalIterations)
	})

	t.Run("EasySuffix", func(t *testing.T) {
		start := time.Now()
		key, totalIterations, err := findConformingKey(ctx, "aaa")
		require.NoError(t, err)
		require.True(t, strings.HasSuffix(key.PublicKeyHex(), "aaa"))
		showKeys(key, start, totalIterations)
	})
}

func TestHexBytes(t *testing.T) {
	{
		sBytes, oddChars := hexBytes("5678")
		require.Equal(t, []byte{0x56, 0x78}, sBytes)
		require.False(t, oddChars)
	}

	{
		sBytes, oddChars := hexBytes("678")
		require.Equal(t, []byte{0x06, 0x78}, sBytes)
		require.True(t, oddChars)
	}
}

func TestSuffixBytesEqual(t *testing.T) {
	require.True(t, suffixBytesEqual([]byte{0x78}, []byte{}, false))

	require.True(t, suffixBytesEqual([]byte{0x78}, []byte{0x78}, false))
	require.True(t, suffixBytesEqual([]byte{0x56, 0x78}, []byte{0x78}, false))
	require.False(t, suffixBytesEqual([]byte{0x78, 0x56}, []byte{0x78}, false))

	require.False(t, suffixBytesEqual([]byte{0x78}, []byte{0x08}, false))
	require.True(t, suffixBytesEqual([]byte{0x78}, []byte{0x08}, true))

	require.True(t, suffixBytesEqual([]byte{0x34, 0x56, 0x78}, []byte{0x56, 0x78}, false))
	require.False(t, suffixBytesEqual([]byte{0x34, 0x56, 0x78}, []byte{0x06, 0x08}, false))
	require.True(t, suffixBytesEqual([]byte{0x34, 0x56, 0x78}, []byte{0x06, 0x78}, true))
}

func TestValidKeySuffix(t *testing.T) {
	testTime := time.Date(2022, 0o7, 11, 1, 1, 1, 1, time.Local)
	require.Equal(t, "83e0724", validKeySuffix(testTime)) // two years in the future
}
