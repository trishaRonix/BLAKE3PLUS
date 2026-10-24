# BLAKE3PLUS

A fork of [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) with native C11 `pthread` multithreading, cgroup CPU quota detection, multi-threaded stream hashing, constant-time MAC verification, and automatic state zeroization.

Outputs are bit-for-bit identical to upstream BLAKE3 across all modes (default, keyed, `derive_key`, and XOF).

## Comparison with Upstream BLAKE3

| Feature | Upstream BLAKE3 | BLAKE3PLUS |
|---|---|---|
| C multithreading | Requires C++ and Intel oneAPI TBB (`BLAKE3_USE_TBB`) | Built-in C11 `pthread` pool (`-DBLAKE3PLUS_ENABLE_PTHREAD -pthread`), no C++ or external dependencies |
| C throughput (1 GiB buffer, 12 threads AVX2) | 3.83 GB/s (1 thread without TBB) | 19.01 GB/s (12 threads, 4.96x speedup) |
| Small input threshold (`update_rayon`) | Always dispatches to Rayon | Runs serially on calling thread below 16 KiB to avoid thread-pool overhead |
| `stdin` / pipe / `--no-mmap` hashing | Single-threaded | Multi-threaded via 4 MiB chunked reader (`update_hasher_reader_mt`) |
| Container CPU limits | Ignores cgroup quotas in C | Reads Linux cgroup v2 (`cpu.max`), v1 (`cpu.cfs_quota_us`), and `sched_getaffinity` |
| Fork safety | None in C | `pthread_atfork` handlers drain and reinitialize worker locks in child processes |
| Memory scrubbing | Optional `zeroize` crate in Rust; manual in C | Volatile wipe + compiler memory fence on `Drop` (Rust) and `blake3plus_hasher_secure_wipe` (C) |
| Constant-time MAC check in C | Not included | `blake3plus_constant_time_eq` and `blake3plus_keyed_mac_verify` |
| `b3sum --check` with `--keyed` / `--derive-key` | Rejected by CLI | Supported |

## Benchmarks

Measured on Intel Core i5-12400F (6C/12T, AVX2), Linux 7.1.5, GCC 13.3.0 (`-O3 -march=native`). Reproduce locally with `make bench`.

### C11 In-Memory Scaling (`blake3plus_hash_buffer_mt`, 1 GiB = 64 MiB x 16)

| Threads | Throughput | Speedup vs 1T |
|---:|---:|---:|
| 1 (upstream C baseline) | 3.83 GB/s | 1.00x |
| 2 | 7.61 GB/s | 1.99x |
| 4 | 12.46 GB/s | 3.25x |
| 6 | 12.11 GB/s | 3.16x |
| 8 | 17.17 GB/s | 4.48x |
| 12 | 19.01 GB/s | 4.96x |

### CLI File & Pipe Throughput (1 GiB file on `/dev/shm` tmpfs)

| Command | Mode | Time (1 GiB) | Throughput |
|---|---|---:|---:|
| `b2sum` | BLAKE2b (1T) | 1.267 s | 0.85 GB/s |
| `sha256sum` | SHA-256 SHA-NI (1T) | 0.697 s | 1.54 GB/s |
| `c/b3p --threads 1` | BLAKE3 C11 `mmap` (1T) | 0.333 s | 3.22 GB/s |
| `b3sum --num-threads 1` | BLAKE3 Rust `mmap` (1T) | 0.328 s | 3.27 GB/s |
| `c/b3p --threads 12` | BLAKE3PLUS C11 `pthread` + `mmap` (12T) | 0.084 s | 12.84 GB/s |
| `b3sum` | BLAKE3PLUS Rust `mmap` (12T) | 0.069 s | 15.52 GB/s |
| `b3sum --no-mmap` | 4 MiB chunked reader (12T) | 0.177 s | 6.05 GB/s |
| `cat file \| b3sum --num-threads 1` | `stdin` pipe (1T, upstream behavior) | 0.614 s | 1.75 GB/s |
| `cat file \| b3sum` | `stdin` pipe (12T `update_hasher_reader_mt`) | 0.405 s | 2.65 GB/s |

## Build and Test

```sh
make          # builds c/b3p and b3sum/target/release/b3sum
make test     # runs C tests (-O3, ASan+UBSan, TSan) and Cargo tests
make bench    # runs 1 GiB single-thread vs multi-thread C benchmark
```

## CLI Usage

```sh
# Hash files using all available cores
./c/b3p file.iso
./b3sum/target/release/b3sum file.iso

# Keyed MAC generation and verification
./c/b3p --keyed <64-hex-key> file.iso
./c/b3p --keyed <64-hex-key> --verify-mac <expected-hex> file.iso
```

## C API (`c/blake3plus.h`)

```c
#include "blake3plus.h"

uint8_t out[BLAKE3_OUT_LEN];

/* Hash memory buffer (0 = auto-detect threads from affinity/cgroup) */
blake3plus_hash_buffer_mt(buf, len, out, BLAKE3_OUT_LEN, 0);

/* Hash file by path or file descriptor (mmap with read() fallback for pipes/sockets) */
blake3plus_hash_file_mmap("archive.tar", out, BLAKE3_OUT_LEN, 0);
blake3plus_hash_fd(fd, out, BLAKE3_OUT_LEN, 0);

/* Constant-time keyed MAC sign and verify (returns 0 on match, -1 on mismatch) */
blake3plus_keyed_mac_sign(key, buf, len, out, BLAKE3_OUT_LEN, 0);
int ok = blake3plus_keyed_mac_verify(key, buf, len, out, BLAKE3_OUT_LEN, 0);
```

## License

Released into the public domain with CC0 1.0, or alternatively under the Apache License 2.0 or LLVM Exceptions. See `LICENSE_CC0`, `LICENSE_A2`, and `LICENSE_A2LLVM`.
