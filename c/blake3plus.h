#ifndef BLAKE3PLUS_H
#define BLAKE3PLUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "blake3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLAKE3PLUS_VERSION_STRING "1.8.7"
#define BLAKE3PLUS_MIN_PARALLEL_SUBTREE_BYTES (64 * 1024)
#define BLAKE3PLUS_WORKER_STACK_SIZE (256 * 1024)

/* Returns available logical CPUs accounting for sched_getaffinity and cgroup quotas. */
BLAKE3_API size_t blake3plus_detect_cgroup_cpu_quota(void);
BLAKE3_API size_t blake3plus_get_effective_cpus(void);
BLAKE3_API size_t blake3plus_get_hw_threads(void);
BLAKE3_API size_t blake3plus_get_active_workers(void);
BLAKE3_API void blake3plus_pool_teardown(void);

BLAKE3_API void blake3plus_hasher_update_mt(blake3_hasher *self,
                                            const void *input,
                                            size_t input_len,
                                            size_t num_threads);

BLAKE3_API void blake3plus_hash_buffer_mt(const void *input,
                                          size_t input_len,
                                          uint8_t *out,
                                          size_t out_len,
                                          size_t num_threads);

BLAKE3_API int blake3plus_hash_file_mmap(const char *filepath,
                                         uint8_t *out,
                                         size_t out_len,
                                         size_t num_threads);

BLAKE3_API int blake3plus_hash_fd(int fd,
                                  uint8_t *out,
                                  size_t out_len,
                                  size_t num_threads);

BLAKE3_API int blake3plus_hasher_hash_fd(blake3_hasher *hasher,
                                         int fd,
                                         size_t num_threads);

BLAKE3_API void blake3plus_secure_zero(void *ptr, size_t len);
BLAKE3_API void blake3plus_hasher_secure_wipe(blake3_hasher *self);
BLAKE3_API int blake3plus_constant_time_eq(const uint8_t *a,
                                           const uint8_t *b,
                                           size_t len);

BLAKE3_API void blake3plus_keyed_mac_sign(const uint8_t key[BLAKE3_KEY_LEN],
                                          const void *input,
                                          size_t input_len,
                                          uint8_t *mac_out,
                                          size_t mac_len,
                                          size_t num_threads);

BLAKE3_API int blake3plus_keyed_mac_verify(const uint8_t key[BLAKE3_KEY_LEN],
                                           const void *input,
                                           size_t input_len,
                                           const uint8_t *expected_mac,
                                           size_t mac_len,
                                           size_t num_threads);

BLAKE3_API void blake3plus_domain_hash(const char *domain_context,
                                       const void *input,
                                       size_t input_len,
                                       uint8_t *out,
                                       size_t out_len,
                                       size_t num_threads);

#ifdef __cplusplus
}
#endif

#endif /* BLAKE3PLUS_H */
