package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExpiryDigitsTimeFormat(t *testing.T) {
	testTime := time.Date(2022, 07, 11, 1, 1, 1, 1, time.Local)
	require.Equal(t, "0722", testTime.Format(expiryDigitsTimeFormat))
}
