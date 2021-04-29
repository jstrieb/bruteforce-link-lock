# Brutefoce Link Lock

This code performs CPU-based parallelized brute forcing of Link Lock URLs.

[Link Lock](https://github.com/jstrieb/link-lock) is a tool to
password-protect URLs by securely encrypting them with AES in the browser.

Specifically, it encrypts with AES in Galois Counter Mode (GCM) and uses
PBKDF2 and 100,000 iterations of SHA256 for key derivation. Encrypted data is
then stored in the URL fragment, rather than on an external server.

There is an [example brute force
tool](https://jstrieb.github.io/link-lock/bruteforce/) for Link Lock URLs
written in JavaScript, but no sane person would try to brute force something
from within their browser. (Though I was pleasantly surprised at the speed of
the single-threaded browser implementation – see [performance](#Performance) below.)

# Quick Start

Compile from source by doing

``` bash
git clone https://github.com/jstrieb/bruteforce-link-lock.git
cd bruteforce-link-lock
go build -o crack
```

This will build an executable called `crack` in the current directory. On
Linux, this can be installed by doing

``` bash
sudo mv crack /usr/local/bin/crack
```

The application can then be called from the command-line

```
$ crack
Usage: crack [options] <Link Lock url>
Options:
  -charset string
        Charset to use for cracking (default "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
```

Test with an example that should be cracked in a few seconds, and will
decrypt to `https://jstrieb.github.io/about` using the password `2`

```
crack "https://jstrieb.github.io/link-lock/#eyJ2IjoiMC4wLjEiLCJlIjoiZEx3Yi9CNitlK0ZjM1B3ZURrbUY2NjdQWFlIV1dsS3dpclhvZmkvRXBFTXU0ZERlVkJuSmUrN1loS2JxQ3RrPSIsImgiOiIxICsgMSA9ID8iLCJpIjoiRDJYd1MyK1EzaHpuUDV1NyJ9"
```

# Performance

This code runs on as many processor cores as possible.

The fastest I have seen this run is between 15 and 20 passphrase attempts per
second per thread (which the browser surprisingly approaches, albeit
single-threaded). The bottleneck is performing 100,000 iterations of SHA256
to do PBKDF2 for every password attempt. Speed improvements in total attempts
per second seem to scale linearly with the number of threads/processor cores
available.

Check out the
[`profiling`](https://github.com/jstrieb/bruteforce-link-lock/tree/profiling)
branch to investigate on your own machine.

# Project Status

I built this as a convenience application and proof-of-concept for myself. I
will try to be responsive to issues, but am not planning to put a lot of time
into adding features or maintaining this project. The one feature I may add
is cracking using a dictionary attack. I am unlikely to merge pull requests
that have not been discussed beforehand, so open an issue before spending
time writing a pull request.

Long-term, I hope that AES-GCM with PBKDF2 is added to
[hashcat](https://hashcat.net/hashcat/) so that this project is no longer
necessary or relevant.