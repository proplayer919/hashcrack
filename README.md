# Hashcrack

Hashcrack is a simple, fast, and free hash bruteforcer for all different hashing algorithms.

## Currently Supported Hash Algorithms

- MD5
- SHA256
- SHA1
- BCRYPT

## Usage

`python3 hashcrack.py -c <hash> [-ha <hash algorithm>] [-sc]`
`-c` - Hash to crack
`-ha` - Hash algorithm - MD5, SHA256, SHA1, BCRYPT (default: SHA256)
`-sc` - Show current information - dynamic (slows down program)

`python3 hashcrack.py -h <hash> [-ha <hash algorithm>]`
`-h` - Hash to crack
`-ha` - Hash algorithm - MD5, SHA256, SHA1, BCRYPT (default: SHA256)
