#define _GNU_SOURCE
#include "blake3plus.h"
#include "blake3_impl.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Internal hook implemented in blake3.c */
extern void blake3_hasher_update_mt_internal(blake3_hasher *self,
                                             const void *input,
                                             size_t input_len);

#define B3P_MAX_WORKERS 64
#define B3P_MAX_SPIN_ITERS 256
#define B3P_MAX_MMAP_BYTES (1ULL << 30)

typedef struct {
  const uint32_t *key;
  uint8_t flags;
  const uint8_t *input;
  size_t input_len;
  uint64_t chunk_counter;
  uint8_t *cvs;
  size_t out_n;
  size_t budget;
} subtree_task_t;

typedef struct __attribute__((aligned(128))) {
  pthread_t thread;
  pthread_mutex_t mtx;
  pthread_cond_t cv;
  pthread_mutex_t done_mtx;
  pthread_cond_t done_cv;
  atomic_int done;
  subtree_task_t *task;
  bool shutdown;
  atomic_bool busy;
} b3p_worker_t;

static b3p_worker_t g_workers[B3P_MAX_WORKERS];
static atomic_size_t g_num_workers = 0;
static pthread_mutex_t g_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_atfork_once = PTHREAD_ONCE_INIT;
static atomic_bool g_pool_fork_active = false;

static _Thread_local size_t tl_thread_budget = 1;

#if defined(__linux__)
static size_t b3p_parse_cgroup_v2_cpu_max(const char *path) {
  FILE *fp = fopen(path, "re");
  if (!fp) {
    return 0;
  }
  char quota_str[64] = {0};
  unsigned long long period = 0;
  if (fscanf(fp, "%63s %llu", quota_str, &period) == 2 && period > 0) {
    fclose(fp);
    if (strcmp(quota_str, "max") != 0) {
      unsigned long long quota = strtoull(quota_str, NULL, 10);
      if (quota > 0) {
        size_t cpus = (size_t)((quota + period - 1) / period);
        return (cpus >= 1) ? cpus : 1;
      }
    }
    return 0;
  }
  fclose(fp);
  return 0;
}
#endif

static size_t b3p_get_cgroup_cpu_quota(void) {
#if defined(__linux__)
  const char *cg_root = getenv("BLAKE3PLUS_CGROUP_ROOT");
  bool custom_root = (cg_root != NULL && cg_root[0] != '\0');
  if (!custom_root) {
    cg_root = "/sys/fs/cgroup";
  }

  char path_buf[PATH_MAX];

  if (!custom_root) {
    FILE *fcg = fopen("/proc/self/cgroup", "re");
    if (fcg) {
      char line[512];
      while (fgets(line, sizeof(line), fcg)) {
        if (strncmp(line, "0::/", 4) == 0) {
          char *sub = line + 3;
          size_t len = strlen(sub);
          while (len > 0 && (sub[len - 1] == '\n' || sub[len - 1] == '\r')) {
            sub[--len] = '\0';
          }
          if (len > 1) {
            snprintf(path_buf, sizeof(path_buf), "%s%s/cpu.max", cg_root, sub);
            size_t slice_cpus = b3p_parse_cgroup_v2_cpu_max(path_buf);
            if (slice_cpus > 0) {
              fclose(fcg);
              return slice_cpus;
            }
          }
          break;
        }
      }
      fclose(fcg);
    }
  }

  snprintf(path_buf, sizeof(path_buf), "%s/cpu.max", cg_root);
  size_t v2_cpus = b3p_parse_cgroup_v2_cpu_max(path_buf);
  if (v2_cpus > 0) {
    return v2_cpus;
  }

  char q_path[PATH_MAX], p_path[PATH_MAX];
  snprintf(q_path, sizeof(q_path), "%s/cpu/cpu.cfs_quota_us", cg_root);
  snprintf(p_path, sizeof(p_path), "%s/cpu/cpu.cfs_period_us", cg_root);
  FILE *fq = fopen(q_path, "re");
  FILE *fp1 = fopen(p_path, "re");
  if (fq && fp1) {
    long long quota = -1, period = 0;
    if (fscanf(fq, "%lld", &quota) == 1 && fscanf(fp1, "%lld", &period) == 1) {
      if (quota > 0 && period > 0) {
        fclose(fq);
        fclose(fp1);
        size_t cpus = (size_t)((quota + period - 1) / period);
        return (cpus >= 1) ? cpus : 1;
      }
    }
  }
  if (fq) fclose(fq);
  if (fp1) fclose(fp1);
#endif
  return 0;
}

BLAKE3_API size_t blake3plus_detect_cgroup_cpu_quota(void) {
  return b3p_get_cgroup_cpu_quota();
}

BLAKE3_API size_t blake3plus_get_effective_cpus(void) {
  size_t affinity_cpus = 0;
#if defined(__linux__)
  cpu_set_t set;
  CPU_ZERO(&set);
  if (sched_getaffinity(0, sizeof(set), &set) == 0) {
    int count = CPU_COUNT(&set);
    if (count >= 1) {
      affinity_cpus = (size_t)count;
    }
  }
#endif
  if (affinity_cpus == 0) {
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    affinity_cpus = (nprocs >= 1) ? (size_t)nprocs : 1;
  }

  size_t cgroup_cpus = b3p_get_cgroup_cpu_quota();
  if (cgroup_cpus > 0 && cgroup_cpus < affinity_cpus) {
    return cgroup_cpus;
  }
  return affinity_cpus;
}

BLAKE3_API size_t blake3plus_get_hw_threads(void) {
  return blake3plus_get_effective_cpus();
}

BLAKE3_API size_t blake3plus_get_active_workers(void) {
  return atomic_load_explicit(&g_num_workers, memory_order_acquire);
}

static void *b3p_worker_loop(void *arg) {
  b3p_worker_t *w = (b3p_worker_t *)arg;
  while (1) {
    pthread_mutex_lock(&w->mtx);
    while (w->task == NULL && !w->shutdown) {
      pthread_cond_wait(&w->cv, &w->mtx);
    }
    if (w->shutdown && w->task == NULL) {
      pthread_mutex_unlock(&w->mtx);
      break;
    }
    subtree_task_t *t = w->task;
    w->task = NULL;
    pthread_mutex_unlock(&w->mtx);

    tl_thread_budget = t->budget;
    t->out_n = blake3_compress_subtree_wide(
        t->input, t->input_len, t->key, t->chunk_counter,
        t->flags, t->cvs, t->budget > 1);

    pthread_mutex_lock(&w->done_mtx);
    atomic_store_explicit(&w->done, 1, memory_order_release);
    pthread_cond_signal(&w->done_cv);
    pthread_mutex_unlock(&w->done_mtx);
  }
  return NULL;
}

static void b3p_atfork_prepare(void) {
  atomic_store_explicit(&g_pool_fork_active, true, memory_order_release);
  pthread_mutex_lock(&g_pool_lock);

  size_t active = atomic_load_explicit(&g_num_workers, memory_order_acquire);
  for (size_t i = 0; i < active; i++) {
    while (atomic_load_explicit(&g_workers[i].busy, memory_order_acquire)) {
      sched_yield();
    }
  }
  for (size_t i = 0; i < active; i++) {
    pthread_mutex_lock(&g_workers[i].mtx);
  }
}

static void b3p_atfork_parent(void) {
  size_t active = atomic_load_explicit(&g_num_workers, memory_order_acquire);
  for (size_t i = active; i > 0; i--) {
    pthread_mutex_unlock(&g_workers[i - 1].mtx);
  }
  pthread_mutex_unlock(&g_pool_lock);
  atomic_store_explicit(&g_pool_fork_active, false, memory_order_release);
}

static void b3p_atfork_child(void) {
  atomic_store_explicit(&g_pool_fork_active, false, memory_order_release);
  atomic_store_explicit(&g_num_workers, 0, memory_order_relaxed);
  pthread_mutex_init(&g_pool_lock, NULL);

  for (size_t i = 0; i < B3P_MAX_WORKERS; i++) {
    pthread_mutex_init(&g_workers[i].mtx, NULL);
    pthread_cond_init(&g_workers[i].cv, NULL);
    pthread_mutex_init(&g_workers[i].done_mtx, NULL);
    pthread_cond_init(&g_workers[i].done_cv, NULL);
    atomic_init(&g_workers[i].busy, false);
    atomic_init(&g_workers[i].done, 0);
    g_workers[i].task = NULL;
    g_workers[i].shutdown = false;
    memset(&g_workers[i].thread, 0, sizeof(pthread_t));
  }
}

static void b3p_register_atfork(void) {
  (void)pthread_atfork(b3p_atfork_prepare, b3p_atfork_parent, b3p_atfork_child);
  atexit(blake3plus_pool_teardown);
}

BLAKE3_API void blake3plus_pool_teardown(void) {
  pthread_mutex_lock(&g_pool_lock);
  size_t current = atomic_load_explicit(&g_num_workers, memory_order_acquire);
  if (current == 0) {
    pthread_mutex_unlock(&g_pool_lock);
    return;
  }

  atomic_store_explicit(&g_num_workers, 0, memory_order_release);

  for (size_t i = 0; i < current; i++) {
    while (atomic_load_explicit(&g_workers[i].busy, memory_order_acquire)) {
      sched_yield();
    }
  }

  for (size_t i = 0; i < current; i++) {
    pthread_mutex_lock(&g_workers[i].mtx);
    g_workers[i].shutdown = true;
    pthread_cond_signal(&g_workers[i].cv);
    pthread_mutex_unlock(&g_workers[i].mtx);
    pthread_join(g_workers[i].thread, NULL);
    pthread_mutex_destroy(&g_workers[i].mtx);
    pthread_cond_destroy(&g_workers[i].cv);
    pthread_mutex_destroy(&g_workers[i].done_mtx);
    pthread_cond_destroy(&g_workers[i].done_cv);
    atomic_store_explicit(&g_workers[i].busy, false, memory_order_relaxed);
  }
  pthread_mutex_unlock(&g_pool_lock);
}

static void b3p_ensure_pool_scaled(size_t desired_threads) {
  pthread_once(&g_atfork_once, b3p_register_atfork);

  size_t hw = blake3plus_get_effective_cpus();
  size_t cap = (desired_threads > 0 && desired_threads < hw) ? desired_threads : hw;
  if (cap > B3P_MAX_WORKERS + 1) {
    cap = B3P_MAX_WORKERS + 1;
  }
  size_t target_workers = (cap > 1) ? (cap - 1) : 0;

  if (atomic_load_explicit(&g_num_workers, memory_order_acquire) >= target_workers) {
    return;
  }

  pthread_mutex_lock(&g_pool_lock);
  size_t current = atomic_load_explicit(&g_num_workers, memory_order_relaxed);
  if (current >= target_workers) {
    pthread_mutex_unlock(&g_pool_lock);
    return;
  }

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  (void)pthread_attr_setstacksize(&attr, BLAKE3PLUS_WORKER_STACK_SIZE);

  for (size_t i = current; i < target_workers; i++) {
    pthread_mutex_init(&g_workers[i].mtx, NULL);
    pthread_cond_init(&g_workers[i].cv, NULL);
    pthread_mutex_init(&g_workers[i].done_mtx, NULL);
    pthread_cond_init(&g_workers[i].done_cv, NULL);
    atomic_init(&g_workers[i].done, 0);
    g_workers[i].task = NULL;
    g_workers[i].shutdown = false;
    atomic_init(&g_workers[i].busy, false);
    if (pthread_create(&g_workers[i].thread, &attr, b3p_worker_loop,
                       &g_workers[i]) != 0) {
      pthread_mutex_destroy(&g_workers[i].mtx);
      pthread_cond_destroy(&g_workers[i].cv);
      pthread_mutex_destroy(&g_workers[i].done_mtx);
      pthread_cond_destroy(&g_workers[i].done_cv);
      target_workers = i;
      break;
    }
  }

  pthread_attr_destroy(&attr);
  atomic_store_explicit(&g_num_workers, target_workers, memory_order_release);
  pthread_mutex_unlock(&g_pool_lock);
}

static b3p_worker_t *b3p_acquire_worker(void) {
  if (atomic_load_explicit(&g_pool_fork_active, memory_order_acquire)) {
    return NULL;
  }
  size_t count = atomic_load_explicit(&g_num_workers, memory_order_acquire);
  for (size_t i = 0; i < count; i++) {
    bool expected = false;
    if (atomic_compare_exchange_strong_explicit(
            &g_workers[i].busy, &expected, true,
            memory_order_acquire, memory_order_relaxed)) {
      return &g_workers[i];
    }
  }
  return NULL;
}

BLAKE3_PRIVATE void blake3plus_compress_subtree_wide_join_pthread(
    const uint32_t key[8], uint8_t flags, bool use_mt,
    const uint8_t *l_input, size_t l_input_len, uint64_t l_chunk_counter,
    uint8_t *l_cvs, size_t *l_n,
    const uint8_t *r_input, size_t r_input_len, uint64_t r_chunk_counter,
    uint8_t *r_cvs, size_t *r_n) {
  size_t current_budget = tl_thread_budget;

  if (!use_mt || current_budget < 2 ||
      r_input_len < BLAKE3PLUS_MIN_PARALLEL_SUBTREE_BYTES ||
      l_input_len < BLAKE3PLUS_MIN_PARALLEL_SUBTREE_BYTES) {
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                        l_chunk_counter, flags, l_cvs, use_mt);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, use_mt);
    return;
  }

  size_t total_len = l_input_len + r_input_len;
  size_t right_budget = (current_budget * r_input_len + (total_len / 2)) / total_len;
  if (right_budget < 1) {
    right_budget = 1;
  } else if (right_budget >= current_budget) {
    right_budget = current_budget - 1;
  }
  size_t left_budget = current_budget - right_budget;

  b3p_worker_t *worker = b3p_acquire_worker();
  if (!worker) {
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                        l_chunk_counter, flags, l_cvs, false);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, false);
    return;
  }

  subtree_task_t right_task = {
      .key = key,
      .flags = flags,
      .input = r_input,
      .input_len = r_input_len,
      .chunk_counter = r_chunk_counter,
      .cvs = r_cvs,
      .out_n = 0,
      .budget = right_budget,
  };

  atomic_store_explicit(&worker->done, 0, memory_order_relaxed);
  pthread_mutex_lock(&worker->mtx);
  worker->task = &right_task;
  pthread_cond_signal(&worker->cv);
  pthread_mutex_unlock(&worker->mtx);

  /* Execute Left subtree on current thread */
  tl_thread_budget = left_budget;
  *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                      l_chunk_counter, flags, l_cvs,
                                      left_budget > 1);

  int spins = 0;
  while (atomic_load_explicit(&worker->done, memory_order_acquire) == 0 &&
         spins < B3P_MAX_SPIN_ITERS) {
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#endif
    spins++;
  }
  if (atomic_load_explicit(&worker->done, memory_order_acquire) == 0) {
    pthread_mutex_lock(&worker->done_mtx);
    while (atomic_load_explicit(&worker->done, memory_order_acquire) == 0) {
      pthread_cond_wait(&worker->done_cv, &worker->done_mtx);
    }
    pthread_mutex_unlock(&worker->done_mtx);
  }

  *r_n = right_task.out_n;
  tl_thread_budget = current_budget;
  atomic_store_explicit(&worker->busy, false, memory_order_release);
}

BLAKE3_API void blake3plus_hasher_update_mt(blake3_hasher *self,
                                            const void *input,
                                            size_t input_len,
                                            size_t num_threads) {
  if (input_len == 0) {
    return;
  }
  size_t hw = blake3plus_get_effective_cpus();
  size_t threads = (num_threads == 0 || num_threads > hw) ? hw : num_threads;
  if (threads <= 1 || input_len < (BLAKE3PLUS_MIN_PARALLEL_SUBTREE_BYTES * 2)) {
    blake3_hasher_update(self, input, input_len);
    return;
  }
  b3p_ensure_pool_scaled(threads);
  tl_thread_budget = threads;
  blake3_hasher_update_mt_internal(self, input, input_len);
  tl_thread_budget = 1;
}

BLAKE3_API void blake3plus_hash_buffer_mt(const void *input,
                                          size_t input_len,
                                          uint8_t *out,
                                          size_t out_len,
                                          size_t num_threads) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3plus_hasher_update_mt(&hasher, input, input_len, num_threads);
  blake3_hasher_finalize(&hasher, out, out_len);
  blake3plus_hasher_secure_wipe(&hasher);
}

static int b3p_hash_fd_internal(int fd,
                                blake3_hasher *hasher,
                                size_t num_threads) {
  struct stat st;
  if (fstat(fd, &st) < 0) {
    return -1;
  }

  if (S_ISREG(st.st_mode) && st.st_size == 0) {
    return 0;
  }

  if (S_ISREG(st.st_mode) && st.st_size > 0) {
    uint64_t remaining = (uint64_t)st.st_size;
    off_t offset = 0;
    bool mmap_ok = true;
    while (remaining > 0) {
      size_t map_len = (remaining > B3P_MAX_MMAP_BYTES)
                           ? (size_t)B3P_MAX_MMAP_BYTES
                           : (size_t)remaining;
      void *mapped = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, fd, offset);
      if (mapped == MAP_FAILED) {
        if (offset == 0) {
          mmap_ok = false;
          break;
        }
        return -1;
      }
      (void)madvise(mapped, map_len, MADV_SEQUENTIAL | MADV_WILLNEED);
      blake3plus_hasher_update_mt(hasher, mapped, map_len, num_threads);
      munmap(mapped, map_len);
      offset += (off_t)map_len;
      remaining -= map_len;
    }
    if (mmap_ok) {
      return 0;
    }
    (void)lseek(fd, 0, SEEK_SET);
  }

  const size_t buf_size = 4 * 1024 * 1024;
  uint8_t *buf = (uint8_t *)malloc(buf_size);
  if (!buf) {
    errno = ENOMEM;
    return -1;
  }

  while (1) {
    ssize_t n = read(fd, buf, buf_size);
    if (n > 0) {
      blake3plus_hasher_update_mt(hasher, buf, (size_t)n, num_threads);
    } else if (n == 0) {
      break;
    } else {
      if (errno == EINTR) {
        continue;
      }
      int saved_errno = errno;
      blake3plus_secure_zero(buf, buf_size);
      free(buf);
      errno = saved_errno;
      return -1;
    }
  }

  blake3plus_secure_zero(buf, buf_size);
  free(buf);
  return 0;
}

BLAKE3_API int blake3plus_hash_fd(int fd,
                                  uint8_t *out,
                                  size_t out_len,
                                  size_t num_threads) {
  if (fd < 0 || !out || out_len == 0) {
    errno = EINVAL;
    return -1;
  }

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  int rc = b3p_hash_fd_internal(fd, &hasher, num_threads);
  if (rc != 0) {
    int saved_errno = errno;
    blake3plus_hasher_secure_wipe(&hasher);
    errno = saved_errno;
    return -1;
  }

  blake3_hasher_finalize(&hasher, out, out_len);
  blake3plus_hasher_secure_wipe(&hasher);
  return 0;
}

BLAKE3_API int blake3plus_hash_file_mmap(const char *filepath,
                                         uint8_t *out,
                                         size_t out_len,
                                         size_t num_threads) {
  if (!filepath) {
    errno = EINVAL;
    return -1;
  }

  int fd = open(filepath, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }

  int rc = blake3plus_hash_fd(fd, out, out_len, num_threads);
  int saved_errno = errno;
  close(fd);
  if (rc != 0) {
    errno = saved_errno;
    return -1;
  }
  return 0;
}

BLAKE3_API void blake3plus_secure_zero(void *ptr, size_t len) {
  if (!ptr || len == 0) {
    return;
  }
  volatile uint8_t *vptr = (volatile uint8_t *)ptr;
  for (size_t i = 0; i < len; i++) {
    vptr[i] = 0;
  }
#if defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

BLAKE3_API void blake3plus_hasher_secure_wipe(blake3_hasher *self) {
  if (!self) {
    return;
  }
  blake3plus_secure_zero(self, sizeof(blake3_hasher));
}

BLAKE3_API int blake3plus_constant_time_eq(const uint8_t *a,
                                           const uint8_t *b,
                                           size_t len) {
  if (!a || !b) {
    return -1;
  }
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }
  uint32_t d = diff;
  return (int)((0U - d) >> 31) ? -1 : 0;
}

BLAKE3_API void blake3plus_keyed_mac_sign(const uint8_t key[BLAKE3_KEY_LEN],
                                          const void *input,
                                          size_t input_len,
                                          uint8_t *mac_out,
                                          size_t mac_len,
                                          size_t num_threads) {
  blake3_hasher hasher;
  blake3_hasher_init_keyed(&hasher, key);
  blake3plus_hasher_update_mt(&hasher, input, input_len, num_threads);
  blake3_hasher_finalize(&hasher, mac_out, mac_len);
  blake3plus_hasher_secure_wipe(&hasher);
}

BLAKE3_API int blake3plus_keyed_mac_verify(const uint8_t key[BLAKE3_KEY_LEN],
                                           const void *input,
                                           size_t input_len,
                                           const uint8_t *expected_mac,
                                           size_t mac_len,
                                           size_t num_threads) {
  if (!key || !expected_mac || mac_len == 0) {
    return -1;
  }

  uint8_t stack_mac[64];
  uint8_t *computed_mac = stack_mac;
  if (mac_len > sizeof(stack_mac)) {
    computed_mac = (uint8_t *)malloc(mac_len);
    if (!computed_mac) {
      return -1;
    }
  }

  blake3plus_keyed_mac_sign(key, input, input_len, computed_mac, mac_len,
                            num_threads);
  int rc = blake3plus_constant_time_eq(computed_mac, expected_mac, mac_len);

  blake3plus_secure_zero(computed_mac, mac_len);
  if (computed_mac != stack_mac) {
    free(computed_mac);
  }
  return rc;
}

BLAKE3_API void blake3plus_domain_hash(const char *domain_context,
                                       const void *input,
                                       size_t input_len,
                                       uint8_t *out,
                                       size_t out_len,
                                       size_t num_threads) {
  blake3_hasher hasher;
  blake3_hasher_init_derive_key(&hasher, domain_context ? domain_context : "");
  blake3plus_hasher_update_mt(&hasher, input, input_len, num_threads);
  blake3_hasher_finalize(&hasher, out, out_len);
  blake3plus_hasher_secure_wipe(&hasher);
}
