# RustCamleFlag

## Installation

### Prerequisites

Install Rust toolchain:

```bash
# macOS / Linux
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Build

```bash
# Clone and build
git clone <repository-url>
cd RustCamelFlag
cargo build --release

# Binary will be at target/release/cfp
```

## Usage

### Start Server

```bash
./target/release/cfp server --passkey <KEY> [--listen 0.0.0.0:8080] [--output-dir ./received] [--log-dir ./logs]
```

Options:
- `--passkey`: Encryption passkey (required)
- `--listen`: Listen address (default: `0.0.0.0:8080`)
- `--output-dir`: Directory for received files (default: `./received`)
- `--log-dir`: Server log directory (default: `./logs`)

### Start Client

```bash
./target/release/cfp client --file <FILE> --server http://host:port --passkey <KEY> [OPTIONS]
```

Options:
- `--file <FILE>`: File to send (required)
- `--server <URL>`: Server URL (required)
- `--passkey <KEY>`: Encryption passkey (if not supplied, will prompt interactively)
- `--chunk-min <bytes>`: Minimum chunk size in bytes (default: `1048576`, 1 MB)
- `--chunk-max <bytes>`: Maximum chunk size in bytes (default: `4194304`, 4 MB)
- `--threads <num>`: Number of parallel sender threads (default: `64`)
- `--interval-min-ms <ms>`: Minimum inter-packet delay per thread (default: `200`)
- `--interval-max-ms <ms>`: Maximum inter-packet delay per thread (default: `800`)