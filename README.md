`ipmd5` database field bruteforcer for Kusaba-X
===============================================

The Kusaba-X imageboard has a security feature to obfuscate the IP addresses associated with posts and bans.
This Golang program takes a list of Kusaba-X IP MD5 hashes and bruteforces the entire range of IPv4 addresses for
de-obfuscation.

The program utilizes channels heavily for running each module within a Goroutine. Bruteforcing is carried out by
multiple Goroutine workers in a fashion that utilizes CPU performance without setting the computer on fire.
