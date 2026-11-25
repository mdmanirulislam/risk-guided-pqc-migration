# Round 1 Reproducibility Package

This archive contains the revised evaluation for submission PAPER022573-1. It supersedes the initial version’s four reference deltas and its prestandard SPHINCS+ measurement.

## Contents

- measure.py produces TLS, certificate, and signature CSVs and records the environment.
- analyze.py reproduces the network simulation and ranking outputs.
- data/environment.json records the measurement configuration.
- data/tls_runs.csv contains 80 validated TLS 1.3 handshakes across four groups with ECDSA authentication.
- data/tls_auth_runs.csv contains 20 hybrid TLS 1.3 handshakes with ML-DSA-65 authentication.
- data/certificate_runs.csv contains 72 parsed DER certificates from 36 independently generated chains.
- data/signature_runs.csv contains 15 software benchmark invocations.
- data/network_grid.csv and data/network_trials.csv contain 432 summaries and all 216,000 packet-simulation trials.
- data/rankings.csv contains policy comparisons and criterion ablation scores.

## Reproduce

Use Python 3.12 or later and OpenSSL 3.5.6 with its default provider and matching shared libraries. No third-party Python packages or external network endpoints are needed. The TLS exchanges use memory buffers. OpenSSL generates temporary local keys for the evaluation. On Windows specify the path to openssl.exe and use an installation with the corresponding libcrypto-3-x64.dll and libssl-3-x64.dll. On Linux the defaults use the discoverable shared libraries. If multiple OpenSSL installations are available, pass --crypto-lib and --ssl-lib explicitly. The code checks that the CLI and loaded library versions match.

    python measure.py --openssl /path/to/openssl --cpu-label "Your CPU model" --out rerun
    python analyze.py --tls-runs rerun/tls_runs.csv --out rerun

Crypto operations use OpenSSL's default random generator. No fixed cryptographic seed is used. ECDSA signatures can vary in encoded size, and software timings vary with host and load. The separate packet simulation uses seed 22573 and 500 trials per condition. To reproduce the simulation exactly using the original measured message lengths, run:

    python analyze.py --tls-runs data/tls_runs.csv --out rerun_model

Each TLS row contains full handshake-message lengths with their four-byte handshake headers. It excludes record, packet, and link-layer bytes. DER rows report key and signature payload lengths and their residual container bytes. For benchmark runs, the reciprocal operations per second is reported in milliseconds. The QUIC-like simulation uses TLS message lengths and a simplified packet model; its timings are not observations of QUIC traffic. The article describes its overhead and loss assumptions.
