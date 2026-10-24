#define _GNU_SOURCE
#include "blake3plus.h"
#include "blake3_impl.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <windows.h>
#endif

/* Internal hook implemented in blake3.c */
extern void blake3_hasher_update_mt_internal(blake3_hasher *self,
                                             const void *input,
                                             size_t input_len);

#define B3P_MAX_WORKERS 64
#define B3P_MAX_SPIN_ITERS 256
#define B3P_TASK_RING_CAP 256
#define B3P_MAX_MMAP_BYTES (1ULL << 30)
#define B3P_STREAM_BUF_SIZE (4 * 1024 * 1024)

typedef enum {
  B3P_TASK_FREE = 0,
  B3P_TASK_ALLOCATED = 1,
  B3P_TASK_QUEUED = 2,
  B3P_TASK_RUNNING = 3,
  B3P_TASK_DONE = 4
} b3p_slot_state_t;

typedef struct {
  const uint32_t *key;
  uint8_t flags;
  const uint8_t *input;
  size_t input_len;
  uint64_t chunk_counter;
  uint8_t *cvs;
  size_t out_n;
  atomic_int state;
  pthread_mutex_t mtx;
  pthread_cond_t cv;
} b3p_task_slot_t;

static b3p_task_slot_t g_slots[B3P_TASK_RING_CAP];
static pthread_once_t g_slots_once = PTHREAD_ONCE_INIT;

static void b3p_init_slots(void) {
  for (size_t i = 0; i < B3P_TASK_RING_CAP; i++) {
    atomic_init(&g_slots[i].state, B3P_TASK_FREE);
    pthread_mutex_init(&g_slots[i].mtx, NULL);
    pthread_cond_init(&g_slots[i].cv, NULL);
  }
}

typedef struct {
  size_t queue[B3P_TASK_RING_CAP];
  size_t head;
  size_t tail;
  size_t count;
  pthread_mutex_t lock;
  pthread_cond_t cv;
  bool shutdown;
} b3p_ring_queue_t;

static b3p_ring_queue_t g_ring = {
  .head = 0, .tail = 0, .count = 0,
  .lock = PTHREAD_MUTEX_INITIALIZER,
  .cv = PTHREAD_COND_INITIALIZER,
  .shutdown = false
};

static pthread_t g_worker_threads[B3P_MAX_WORKERS];
static atomic_size_t g_num_workers = 0;
static pthread_mutex_t g_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_atfork_once = PTHREAD_ONCE_INIT;
static atomic_bool g_pool_fork_active = false;

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
#elif defined(_WIN32)
  SYSTEM_INFO sysinfo;
  GetSystemInfo(&sysinfo);
  affinity_cpus = (size_t)sysinfo.dwNumberOfProcessors;
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

static size_t b3p_acquire_free_slot(void) {
  static _Thread_local size_t tl_start = 0;
  size_t start = tl_start;
  for (size_t i = 0; i < B3P_TASK_RING_CAP; i++) {
    size_t idx = (start + i) % B3P_TASK_RING_CAP;
    int exp = B3P_TASK_FREE;
    if (atomic_compare_exchange_strong_explicit(&g_slots[idx].state, &exp, B3P_TASK_ALLOCATED,
                                                memory_order_acq_rel, memory_order_acquire)) {
      tl_start = (idx + 1) % B3P_TASK_RING_CAP;
      return idx;
    }
  }
  return SIZE_MAX;
}

static bool b3p_ring_push(size_t slot_idx) {
  pthread_mutex_lock(&g_ring.lock);
  if (g_ring.count == B3P_TASK_RING_CAP) {
    pthread_mutex_unlock(&g_ring.lock);
    return false;
  }
  g_ring.queue[g_ring.tail] = slot_idx;
  g_ring.tail = (g_ring.tail + 1) % B3P_TASK_RING_CAP;
  g_ring.count++;
  pthread_cond_signal(&g_ring.cv);
  pthread_mutex_unlock(&g_ring.lock);
  return true;
}

static size_t b3p_ring_try_pop(void) {
  pthread_mutex_lock(&g_ring.lock);
  if (g_ring.count == 0) {
    pthread_mutex_unlock(&g_ring.lock);
    return SIZE_MAX;
  }
  size_t slot = g_ring.queue[g_ring.head];
  g_ring.head = (g_ring.head + 1) % B3P_TASK_RING_CAP;
  g_ring.count--;
  pthread_mutex_unlock(&g_ring.lock);
  return slot;
}

static void b3p_execute_slot(size_t slot_idx) {
  b3p_task_slot_t *slot = &g_slots[slot_idx];
  int exp = B3P_TASK_QUEUED;
  if (!atomic_compare_exchange_strong_explicit(&slot->state, &exp, B3P_TASK_RUNNING,
                                              memory_order_acq_rel, memory_order_acquire)) {
    return;
  }
  slot->out_n = blake3_compress_subtree_wide(
      slot->input, slot->input_len, slot->key, slot->chunk_counter,
      slot->flags, slot->cvs, true);

  pthread_mutex_lock(&slot->mtx);
  atomic_store_explicit(&slot->state, B3P_TASK_DONE, memory_order_release);
  pthread_cond_broadcast(&slot->cv);
  pthread_mutex_unlock(&slot->mtx);
}

static void *b3p_worker_loop(void *arg) {
  (void)arg;
  while (1) {
    pthread_mutex_lock(&g_ring.lock);
    while (g_ring.count == 0 && !g_ring.shutdown) {
      pthread_cond_wait(&g_ring.cv, &g_ring.lock);
    }
    if (g_ring.shutdown && g_ring.count == 0) {
      pthread_mutex_unlock(&g_ring.lock);
      break;
    }
    size_t slot_idx = g_ring.queue[g_ring.head];
    g_ring.head = (g_ring.head + 1) % B3P_TASK_RING_CAP;
    g_ring.count--;
    pthread_mutex_unlock(&g_ring.lock);

    b3p_execute_slot(slot_idx);
  }
  return NULL;
}

static void b3p_atfork_prepare(void) {
  atomic_store_explicit(&g_pool_fork_active, true, memory_order_release);
  pthread_mutex_lock(&g_pool_lock);
  pthread_mutex_lock(&g_ring.lock);
}

static void b3p_atfork_parent(void) {
  pthread_mutex_unlock(&g_ring.lock);
  pthread_mutex_unlock(&g_pool_lock);
  atomic_store_explicit(&g_pool_fork_active, false, memory_order_release);
}

static void b3p_atfork_child(void) {
  atomic_store_explicit(&g_pool_fork_active, false, memory_order_release);
  atomic_store_explicit(&g_num_workers, 0, memory_order_relaxed);
  pthread_mutex_init(&g_pool_lock, NULL);
  pthread_mutex_init(&g_ring.lock, NULL);
  pthread_cond_init(&g_ring.cv, NULL);
  g_ring.head = 0;
  g_ring.tail = 0;
  g_ring.count = 0;
  g_ring.shutdown = false;
  for (size_t i = 0; i < B3P_TASK_RING_CAP; i++) {
    atomic_init(&g_slots[i].state, B3P_TASK_FREE);
    pthread_mutex_init(&g_slots[i].mtx, NULL);
    pthread_cond_init(&g_slots[i].cv, NULL);
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

  pthread_mutex_lock(&g_ring.lock);
  g_ring.shutdown = true;
  pthread_cond_broadcast(&g_ring.cv);
  pthread_mutex_unlock(&g_ring.lock);

  for (size_t i = 0; i < current; i++) {
    pthread_join(g_worker_threads[i], NULL);
  }

  pthread_mutex_lock(&g_ring.lock);
  g_ring.head = 0;
  g_ring.tail = 0;
  g_ring.count = 0;
  g_ring.shutdown = false;
  pthread_mutex_unlock(&g_ring.lock);

  pthread_mutex_unlock(&g_pool_lock);
}

static void b3p_ensure_pool_scaled(size_t desired_threads) {
  pthread_once(&g_slots_once, b3p_init_slots);
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
    if (pthread_create(&g_worker_threads[i], &attr, b3p_worker_loop, NULL) != 0) {
      target_workers = i;
      break;
    }
  }

  pthread_attr_destroy(&attr);
  atomic_store_explicit(&g_num_workers, target_workers, memory_order_release);
  pthread_mutex_unlock(&g_pool_lock);
}

BLAKE3_PRIVATE void blake3plus_compress_subtree_wide_join_pthread(
    const uint32_t key[8], uint8_t flags, bool use_mt,
    const uint8_t *l_input, size_t l_input_len, uint64_t l_chunk_counter,
    uint8_t *l_cvs, size_t *l_n,
    const uint8_t *r_input, size_t r_input_len, uint64_t r_chunk_counter,
    uint8_t *r_cvs, size_t *r_n) {
  if (!use_mt ||
      r_input_len < BLAKE3PLUS_MIN_PARALLEL_SUBTREE_BYTES ||
      l_input_len < BLAKE3PLUS_MIN_PARALLEL_SUBTREE_BYTES ||
      atomic_load_explicit(&g_num_workers, memory_order_acquire) == 0 ||
      atomic_load_explicit(&g_pool_fork_active, memory_order_acquire)) {
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                        l_chunk_counter, flags, l_cvs, use_mt);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, use_mt);
    return;
  }

  size_t slot_idx = b3p_acquire_free_slot();
  if (slot_idx == SIZE_MAX) {
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                        l_chunk_counter, flags, l_cvs, false);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, false);
    return;
  }

  b3p_task_slot_t *slot = &g_slots[slot_idx];
  slot->key = key;
  slot->flags = flags;
  slot->input = r_input;
  slot->input_len = r_input_len;
  slot->chunk_counter = r_chunk_counter;
  slot->cvs = r_cvs;
  slot->out_n = 0;
  atomic_store_explicit(&slot->state, B3P_TASK_QUEUED, memory_order_release);

  bool pushed = b3p_ring_push(slot_idx);
  if (!pushed) {
    atomic_store_explicit(&slot->state, B3P_TASK_FREE, memory_order_release);
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                        l_chunk_counter, flags, l_cvs, false);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, false);
    return;
  }

  /* Execute left subtree on current thread */
  *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                      l_chunk_counter, flags, l_cvs, true);

  /* Now handle right subtree */
  int exp = B3P_TASK_QUEUED;
  if (atomic_compare_exchange_strong_explicit(&slot->state, &exp, B3P_TASK_RUNNING,
                                              memory_order_acq_rel, memory_order_acquire)) {
    /* Worker hasn't picked it up yet! Caller computes it directly */
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, true);
    atomic_store_explicit(&slot->state, B3P_TASK_FREE, memory_order_release);
  } else {
    /* A worker claimed or is running it. Help other tasks or wait */
    while (atomic_load_explicit(&slot->state, memory_order_acquire) != B3P_TASK_DONE) {
      size_t other = b3p_ring_try_pop();
      if (other != SIZE_MAX) {
        b3p_execute_slot(other);
      } else {
        int spins = 0;
        while (atomic_load_explicit(&slot->state, memory_order_acquire) != B3P_TASK_DONE &&
               spins < B3P_MAX_SPIN_ITERS) {
#if defined(__x86_64__) || defined(__i386__)
          __builtin_ia32_pause();
#endif
          spins++;
        }
        if (atomic_load_explicit(&slot->state, memory_order_acquire) != B3P_TASK_DONE) {
          pthread_mutex_lock(&slot->mtx);
          while (atomic_load_explicit(&slot->state, memory_order_acquire) != B3P_TASK_DONE) {
            pthread_cond_wait(&slot->cv, &slot->mtx);
          }
          pthread_mutex_unlock(&slot->mtx);
        }
      }
    }
    *r_n = slot->out_n;
    atomic_store_explicit(&slot->state, B3P_TASK_FREE, memory_order_release);
  }
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
  blake3_hasher_update_mt_internal(self, input, input_len);
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

/* SIGBUS handler to protect against concurrent file truncation during mmap */
static atomic_bool g_sigbus_active = false;
static _Thread_local sigjmp_buf tl_sigbus_env;
static _Thread_local volatile sig_atomic_t tl_sigbus_enabled = 0;
static struct sigaction b3p_old_sigbus_sa;
static pthread_once_t b3p_sigbus_once = PTHREAD_ONCE_INIT;

static void b3p_sigbus_handler(int sig, siginfo_t *info, void *ctx) {
  (void)sig; (void)info; (void)ctx;
  if (atomic_load_explicit(&g_sigbus_active, memory_order_acquire)) {
    if (tl_sigbus_enabled) {
      siglongjmp(tl_sigbus_env, 1);
    }
    pthread_exit(NULL);
  }
  if (b3p_old_sigbus_sa.sa_handler != SIG_DFL &&
      b3p_old_sigbus_sa.sa_handler != SIG_IGN &&
      b3p_old_sigbus_sa.sa_sigaction != NULL) {
    if (b3p_old_sigbus_sa.sa_flags & SA_SIGINFO) {
      b3p_old_sigbus_sa.sa_sigaction(sig, info, ctx);
    } else {
      b3p_old_sigbus_sa.sa_handler(sig);
    }
  } else {
    signal(SIGBUS, SIG_DFL);
    raise(SIGBUS);
  }
}

static void b3p_init_sigbus(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = b3p_sigbus_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGBUS, &sa, &b3p_old_sigbus_sa);
}

/* Double-buffered streaming reader context */
typedef struct {
  int fd;
  uint8_t *buf[2];
  size_t buf_sz;
  ssize_t bytes_read[2];
  int err[2];
  atomic_int ready[2];
  atomic_bool stop;
  pthread_t thread;
} b3p_stream_pipe_t;

static void *b3p_stream_reader_worker(void *arg) {
  b3p_stream_pipe_t *pipe = (b3p_stream_pipe_t *)arg;
  size_t cur = 0;
  while (!atomic_load_explicit(&pipe->stop, memory_order_acquire)) {
    while (atomic_load_explicit(&pipe->ready[cur], memory_order_acquire) == 1 &&
           !atomic_load_explicit(&pipe->stop, memory_order_acquire)) {
      sched_yield();
    }
    if (atomic_load_explicit(&pipe->stop, memory_order_acquire)) {
      break;
    }
    ssize_t n = 0;
    while (1) {
      n = read(pipe->fd, pipe->buf[cur], pipe->buf_sz);
      if (n < 0 && errno == EINTR) {
        continue;
      }
      break;
    }
    pipe->bytes_read[cur] = n;
    pipe->err[cur] = (n < 0) ? errno : 0;
    atomic_store_explicit(&pipe->ready[cur], 1, memory_order_release);
    if (n <= 0) {
      break;
    }
    cur = 1 - cur;
  }
  return NULL;
}

static int __attribute__((noinline)) b3p_safe_mmap_update(
    blake3_hasher *hasher, void *mapped, size_t map_len, size_t num_threads) {
  atomic_store_explicit(&g_sigbus_active, true, memory_order_release);
  tl_sigbus_enabled = 1;
  if (sigsetjmp(tl_sigbus_env, 1) != 0) {
    tl_sigbus_enabled = 0;
    atomic_store_explicit(&g_sigbus_active, false, memory_order_release);
    return -1;
  }
  blake3plus_hasher_update_mt(hasher, mapped, map_len, num_threads);
  tl_sigbus_enabled = 0;
  atomic_store_explicit(&g_sigbus_active, false, memory_order_release);
  return 0;
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
    pthread_once(&b3p_sigbus_once, b3p_init_sigbus);
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

      if (b3p_safe_mmap_update(hasher, mapped, map_len, num_threads) != 0) {
        munmap(mapped, map_len);
        mmap_ok = false;
        break;
      }

      munmap(mapped, map_len);
      offset += (off_t)map_len;
      remaining -= map_len;
    }
    if (mmap_ok) {
      return 0;
    }
    (void)lseek(fd, 0, SEEK_SET);
  }

  /* Pipelined double-buffering for pipes, sockets, and non-mmap regular files */
  b3p_stream_pipe_t pipe;
  pipe.fd = fd;
  pipe.buf_sz = B3P_STREAM_BUF_SIZE;
  pipe.buf[0] = (uint8_t *)malloc(pipe.buf_sz);
  pipe.buf[1] = (uint8_t *)malloc(pipe.buf_sz);
  if (!pipe.buf[0] || !pipe.buf[1]) {
    free(pipe.buf[0]);
    free(pipe.buf[1]);
    errno = ENOMEM;
    return -1;
  }
  atomic_init(&pipe.ready[0], 0);
  atomic_init(&pipe.ready[1], 0);
  atomic_init(&pipe.stop, false);

  if (pthread_create(&pipe.thread, NULL, b3p_stream_reader_worker, &pipe) != 0) {
    free(pipe.buf[0]);
    free(pipe.buf[1]);
    errno = EAGAIN;
    return -1;
  }

  size_t cur = 0;
  int stream_rc = 0;
  while (1) {
    while (atomic_load_explicit(&pipe.ready[cur], memory_order_acquire) == 0) {
      sched_yield();
    }
    if (pipe.bytes_read[cur] < 0) {
      errno = pipe.err[cur];
      stream_rc = -1;
      break;
    }
    if (pipe.bytes_read[cur] == 0) {
      break;
    }
    blake3plus_hasher_update_mt(hasher, pipe.buf[cur], (size_t)pipe.bytes_read[cur], num_threads);
    atomic_store_explicit(&pipe.ready[cur], 0, memory_order_release);
    cur = 1 - cur;
  }

  atomic_store_explicit(&pipe.stop, true, memory_order_release);
  pthread_join(pipe.thread, NULL);
  blake3plus_secure_zero(pipe.buf[0], pipe.buf_sz);
  blake3plus_secure_zero(pipe.buf[1], pipe.buf_sz);
  free(pipe.buf[0]);
  free(pipe.buf[1]);
  return stream_rc;
}

BLAKE3_API int blake3plus_hasher_hash_fd(blake3_hasher *hasher,
                                         int fd,
                                         size_t num_threads) {
  if (!hasher || fd < 0) {
    errno = EINVAL;
    return -1;
  }
  return b3p_hash_fd_internal(fd, hasher, num_threads);
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
