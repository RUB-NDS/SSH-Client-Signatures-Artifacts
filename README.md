# On the Security of SSH Client Signatures - Artifacts

This repository contains artifacts for the paper "On the Security of SSH Client Signatures", to be published.

## Repository Overview

```text
.
├── client_keys
│   ├── env_docker                 # Dockerfiles for creating the Elasticsearch infrastructure used for evalutaion
│   ├── eval_results               # Evaluation results produced by scripts under eval_scripts
│   └── eval_scripts               # Scripts for evaluating a dataset of SSH public keys gathered with the SSH-Key-Scraper tool
├── putty_attack                   # Artifacts related to the PuTTY attack
├── tools
│   ├── RSA-Factorability-Tool     # Python implementation for an optimized batch-gcd algorithm used to find common factors
│   ├── SSH-Client-Nonce-Sampler   # A tool written in Go that can be used to analyze the determinism and bias of SSH client nonces
│   └── SSH-Key-Scraper            # A tool written in Go that can collect SSH public keys from GitHub, GitLab, and Launchpad
└── README.md
```
