# Spring '83 keygen

A very simple Go-based implementation for generating a [Spring '83 conforming key](https://github.com/robinsloan/spring-83/blob/main/draft-20220629.md#key-format). This involves generating by brute force until finding a key which contains a suffix containing a target expiry date and magic numbers. Takes about 10 minutes on my M1 Mac.

I know this duplicates work other people have done, but I did it for fun.

## Usage

Generate a conforming key that will expire two years from this month:

    $ go run main.go
    Brute forcing a Spring '83 key (this could take a while)
    Succeeded in 8m42.974918875s with 150736470 iterations
    private key (hex): 3d926f386f093e02530a4a439f953801aeb92af14bc98a3edd3df40a9bc422afc94f5fb1b38b4d51716e9525740f74027e151a624e2d01c762c8a4edf83e1124
    public key (hex):  c94f5fb1b38b4d51716e9525740f74027e151a624e2d01c762c8a4edf83e1124

## Development

Run the test suite:

    $ go test .

Run lint:

    $ golangci-lint --fix