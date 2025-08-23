# On the Security of SSH Client Signatures - Artifacts

## SSH Client / Agent Nonce Sampler

This tool is designed to automatically sample DSA, ECDSA, and EdDSA nonces
from SSH clients during authentication in a lab environment. It also supports
sampling nonces from SSH agents by directly connecting to the UNIX socket of
the agent. Based on the samples nonces, the tool can determine whether
deterministic nonces are used by the client, and measure potential bias in the
nonce generation.

> [!IMPORTANT]
> To determine whether nonces are generated randomly, the tool tries to sample
> at least two signatures computed over the same message. To do so, a partial
> success is indicated to the client, encouraging further authentication attempts
> in the same session. This may not work for all SSH clients depending on their
> implementation. If the tool cannot sample two or more signatures, only
> well-known deterministic schemes can be ruled out. Sometimes, multiple
> authentication attempts can also be achieved by configuring the same key
> multiple times.

## Building

Make sure Golang 1.23.0 or newer is available. To build the tool, simply run
`go build` inside this directory.

## Usage

```bash
$ ./SSH-Client-Nonce-Sampler --help
NAME:
   ssh-client-nonce-sampler - Test your SSH client's signature

USAGE:
   ssh-client-nonce-sampler [global options] command [command options]

DESCRIPTION:
   A tool to measure DSA / ECDSA / Ed25519 nonce determinism in SSH client signature generation and test for potential bias

COMMANDS:
   bias         sample nonces and test for bias
   determinism  sample two nonces from the same connection and test for determinism
   help, h      Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
```

```bash
$ ./SSH-Client-Nonce-Sampler.exe bias --help
NAME:
   ssh-client-nonce-sampler bias - sample nonces and test for bias

USAGE:
   ssh-client-nonce-sampler bias [command options] [arguments...]

OPTIONS:
   --workers value, -j value             number of workers (default: 24)
   --minimum-signatures value, -n value  minimum number of signatures to collect (default: 20000)
   --private-key-file value, -k value    path to the private key file containing the client's private key
   --client-command value, -c value      client command to use for connecting to the server using ECDSA user authentication (placeholders: %host% and %port%)
   --timeout value, -t value             listen timeout in milliseconds (default: 1000)
   --agent, -a                           connect to the local SSH agent identified via SSH_AUTH_SOCK instead to generate signatures (default: false)
   --no-partial-success                  do not indicate a partial success during authentication. use with deterministic nonces to avoid false positives. (default: false)
   --help, -h                            show help
```

```bash
$ ./SSH-Client-Nonce-Sampler.exe determinism --help
NAME:
   ssh-client-nonce-sampler determinism - sample two nonces from the same connection and test for determinism

USAGE:
   ssh-client-nonce-sampler determinism [command options] [arguments...]

OPTIONS:
   --private-key-file value, -k value  path to the private key file containing the client's private key
   --timeout value, -t value           listen timeout in milliseconds (default: 1000)
   --agent, -a                         connect to the local SSH agent identified via SSH_AUTH_SOCK instead to generate signatures (default: false)
   --no-partial-success                do not indicate a partial success during authentication. this may hinder detection of random nonces and is generally not recommended. (default: true)
   --help, -h                          show hel
```
