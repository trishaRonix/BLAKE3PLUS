use crate::{Hash, Hasher, KEY_LEN, OUT_LEN};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub const STREAM_BUFFER_BYTES: usize = 4 * 1024 * 1024;

#[inline]
pub fn secure_zero_slice(buf: &mut [u8]) {
    for b in buf {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline]
pub fn constant_time_eq_slice(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(a, b)
}

pub fn effective_cpus() -> usize {
    let affinity_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    #[cfg(target_os = "linux")]
    {
        if let Some(cg_cpus) = read_linux_cgroup_quota() {
            if cg_cpus > 0 && cg_cpus < affinity_cpus {
                return cg_cpus;
            }
        }
    }

    affinity_cpus.max(1)
}

#[cfg(target_os = "linux")]
fn parse_v2_cpu_max(path: &str) -> Option<usize> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut parts = content.split_whitespace();
    let (quota_str, period_str) = (parts.next()?, parts.next()?);
    if quota_str != "max" {
        let quota = quota_str.parse::<u64>().ok()?;
        let period = period_str.parse::<u64>().ok()?;
        if quota > 0 && period > 0 {
            let cpus = ((quota + period - 1) / period) as usize;
            return Some(cpus.max(1));
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_linux_cgroup_quota() -> Option<usize> {
    let custom_root = std::env::var("BLAKE3PLUS_CGROUP_ROOT")
        .ok()
        .filter(|s| !s.is_empty());
    let cg_root = custom_root.as_deref().unwrap_or("/sys/fs/cgroup");

    if custom_root.is_none() {
        if let Ok(cg_self) = std::fs::read_to_string("/proc/self/cgroup") {
            for line in cg_self.lines() {
                if let Some(sub) = line.strip_prefix("0::/") {
                    let sub = sub.trim();
                    if !sub.is_empty() {
                        let path = format!("{}/{}/cpu.max", cg_root, sub);
                        if let Some(cpus) = parse_v2_cpu_max(&path) {
                            return Some(cpus);
                        }
                    }
                    break;
                }
            }
        }
    }

    if let Some(cpus) = parse_v2_cpu_max(&format!("{}/cpu.max", cg_root)) {
        return Some(cpus);
    }

    if let (Ok(q_str), Ok(p_str)) = (
        std::fs::read_to_string(format!("{}/cpu/cpu.cfs_quota_us", cg_root)),
        std::fs::read_to_string(format!("{}/cpu/cpu.cfs_period_us", cg_root)),
    ) {
        if let (Ok(quota), Ok(period)) = (
            q_str.trim().parse::<i64>(),
            p_str.trim().parse::<i64>(),
        ) {
            if quota > 0 && period > 0 {
                let cpus = ((quota + period - 1) / period) as usize;
                return Some(cpus.max(1));
            }
        }
    }

    None
}

#[cfg(feature = "rayon")]
pub fn build_optimal_thread_pool(
    num_threads: Option<usize>,
) -> Result<rayon_core::ThreadPool, rayon_core::ThreadPoolBuildError> {
    let hw = effective_cpus();
    let threads = match num_threads {
        Some(0) | None => hw,
        Some(n) => n.min(hw),
    };
    rayon_core::ThreadPoolBuilder::new()
        .num_threads(threads)
        .stack_size(256 * 1024)
        .build()
}

pub fn update_hasher_reader_mt(hasher: &mut Hasher, mut reader: impl Read) -> io::Result<u64> {
    let mut buf = vec![0u8; STREAM_BUFFER_BYTES];
    let mut total = 0u64;
    let mut filled = 0usize;

    let res = (|| -> io::Result<u64> {
        loop {
            match reader.read(&mut buf[filled..]) {
                Ok(0) => {
                    if filled > 0 {
                        #[cfg(feature = "rayon")]
                        hasher.update_rayon(&buf[..filled]);
                        #[cfg(not(feature = "rayon"))]
                        hasher.update(&buf[..filled]);
                        total += filled as u64;
                    }
                    return Ok(total);
                }
                Ok(n) => {
                    filled += n;
                    if filled == buf.len() {
                        #[cfg(feature = "rayon")]
                        hasher.update_rayon(&buf);
                        #[cfg(not(feature = "rayon"))]
                        hasher.update(&buf);
                        total += filled as u64;
                        filled = 0;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    })();

    secure_zero_slice(&mut buf);
    res
}

#[inline]
pub fn hash_mt(input: &[u8]) -> Hash {
    let mut hasher = Hasher::new();
    #[cfg(feature = "rayon")]
    hasher.update_rayon(input);
    #[cfg(not(feature = "rayon"))]
    hasher.update(input);
    hasher.finalize()
}

#[inline]
pub fn hash_file_mt(path: impl AsRef<Path>) -> io::Result<Hash> {
    let mut file = File::open(path.as_ref())?;
    let mut hasher = Hasher::new();
    #[cfg(feature = "mmap")]
    {
        if let Some(mmap) = crate::io::maybe_mmap_file(&mut file)? {
            #[cfg(feature = "rayon")]
            hasher.update_rayon(&mmap);
            #[cfg(not(feature = "rayon"))]
            hasher.update(&mmap);
            return Ok(hasher.finalize());
        }
    }
    update_hasher_reader_mt(&mut hasher, &mut file)?;
    Ok(hasher.finalize())
}

#[inline]
pub fn keyed_mac_sign(key: &[u8; KEY_LEN], input: &[u8]) -> Hash {
    let mut hasher = Hasher::new_keyed(key);
    #[cfg(feature = "rayon")]
    hasher.update_rayon(input);
    #[cfg(not(feature = "rayon"))]
    hasher.update(input);
    hasher.finalize()
}

#[inline]
pub fn keyed_mac_verify(key: &[u8; KEY_LEN], input: &[u8], expected_mac: &[u8; OUT_LEN]) -> bool {
    let computed = keyed_mac_sign(key, input);
    constant_time_eq_slice(computed.as_bytes(), expected_mac)
}

#[inline]
pub fn domain_hash_mt(domain_context: &str, input: &[u8]) -> Hash {
    let mut hasher = Hasher::new_derive_key(domain_context);
    #[cfg(feature = "rayon")]
    hasher.update_rayon(input);
    #[cfg(not(feature = "rayon"))]
    hasher.update(input);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paint_pattern(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
    }

    #[test]
    fn test_mt_matches_reference_across_sizes() {
        let sizes = [
            0usize,
            1,
            63,
            64,
            65,
            1023,
            1024,
            1025,
            16 * 1024,
            64 * 1024 - 1,
            64 * 1024,
            64 * 1024 + 1,
            128 * 1024 + 7,
            2 * 1024 * 1024 + 333,
        ];
        let mut max_buf = vec![0u8; 2 * 1024 * 1024 + 333];
        paint_pattern(&mut max_buf);

        for &len in &sizes {
            let slice = &max_buf[..len];
            let expected = crate::hash(slice);
            let actual = hash_mt(slice);
            assert_eq!(expected, actual, "mismatch at len={}", len);
        }
    }

    #[test]
    fn test_secure_wipe_zeroizes_hasher_state() {
        let key = [0xAAu8; KEY_LEN];
        let mut h = Hasher::new_keyed(&key);
        let mut data = vec![0x55u8; 16384];
        paint_pattern(&mut data);
        h.update(&data);

        assert!(h.key.iter().any(|&w| w != 0));
        assert!(!h.cv_stack.is_empty());

        h.secure_wipe();

        assert!(h.key.iter().all(|&w| w == 0));
        assert!(h.chunk_state.cv.iter().all(|&w| w == 0));
        assert!(h.chunk_state.buf.0.iter().all(|&b| b == 0));
        assert_eq!(h.chunk_state.buf_len, 0);
        assert_eq!(h.chunk_state.blocks_compressed, 0);
        assert_eq!(h.cv_stack.len(), 0);
    }

    #[test]
    fn test_constant_time_mac_bit_flips() {
        let key = [0x42u8; KEY_LEN];
        let mut msg = vec![0u8; 8192];
        paint_pattern(&mut msg);

        let tag = keyed_mac_sign(&key, &msg);
        assert!(keyed_mac_verify(&key, &msg, tag.as_bytes()));

        for bit in 0..(OUT_LEN * 8) {
            let mut forged = *tag.as_bytes();
            forged[bit / 8] ^= 1u8 << (bit % 8);
            assert!(
                !keyed_mac_verify(&key, &msg, &forged),
                "forged MAC accepted at bit {}",
                bit
            );
        }
    }

    #[test]
    fn test_streaming_reader_mt_matches_oneshot() {
        let mut data = vec![0u8; 5 * 1024 * 1024 + 911];
        paint_pattern(&mut data);

        let expected = hash_mt(&data);
        let mut hasher = Hasher::new();
        let n = update_hasher_reader_mt(&mut hasher, std::io::Cursor::new(&data)).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(expected, hasher.finalize());
    }

    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn test_hash_file_mt() {
        let mut data = vec![0u8; 128 * 1024 + 13];
        paint_pattern(&mut data);
        let expected = hash_mt(&data);

        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_b3p_hash_file_mt.bin");
        std::fs::write(&file_path, &data).unwrap();

        let actual = hash_file_mt(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);
        assert_eq!(expected, actual);
    }
}
