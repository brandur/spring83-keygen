# Spring '83 keygen

A very simple Go-based implementation for generating a [Spring '83 conforming key](https://github.com/robinsloan/spring-83/blob/main/draft-20220629.md#key-format), which contains a suffix containing a target expiry date and magic numbers.

I know this duplicates work other people have done, but I did it for fun.

## Usage

Generate a conforming key that will expire two years from this month:

    go run main.go

## Development

Run the test suite:

    go test .

Run lint:

    golangci-lint --fix