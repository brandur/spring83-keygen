# Spring '83 keygen [![Build Status](https://github.com/brandur/spring83-keygen/workflows/spring83-keygen%20CI/badge.svg)](https://github.com/brandur/spring83-keygen/actions)

A very simple Go-based implementation for generating a [Spring '83 conforming key](https://github.com/robinsloan/spring-83/blob/main/draft-20220629.md#key-format). This involves generating by brute force until finding a key which contains a suffix containing a target expiry date and magic numbers. Takes ~3 to 10 minutes on my M1 Mac.

I know this duplicates work other people have done, but I did it for fun.

## Usage

Generate a conforming key that will expire two years from this month:

    $ go run main.go
    Brute forcing a Spring '83 key (this could take a while)
    Succeeded in 3m0.280434083s with 54276464 iterations
    Private key (hex): 90ba51828ecc30132d4707d55d24456fbd726514cf56ab4668b62392798e2540
    Public  key (hex): e90e9091b13a6e5194c1fed2728d1fdb6de7df362497d877b8c0b8f0883e1124

## Development

Run the test suite:

    $ go test .

Run lint:

    $ golangci-lint --fix
