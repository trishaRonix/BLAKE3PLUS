#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "blake3plus.h"

const char *__tsan_default_options(void);
const char *__tsan_default_options(void) {
  return "die_after_fork=0";
}

static void fill_pattern(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    buf[i] = (uint8_t)(i % 251);
  }
}

static void test_unaligned_subtrees(void) {
  static const size_t sizes[] = {
      0,       1,       63,      64,      65,      1023,    1024,    1025,
      16384,   65535,   65536,   65537,   131072,  131079,  1048576, 2097485,
  };
  size_t max_len = sizes[sizeof(sizes) / sizeof(sizes[0]) - 1];
  uint8_t *buf = (uint8_t *)malloc(max_len);
  assert(buf != NULL);
  fill_pattern(buf, max_len);

  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    size_t len = sizes[i];
    uint8_t expected[BLAKE3_OUT_LEN];
    blake3_hasher h_st;
    blake3_hasher_init(&h_st);
    blake3_hasher_update(&h_st, buf, len);
    blake3_hasher_finalize(&h_st, expected, BLAKE3_OUT_LEN);

    for (size_t threads = 1; threads <= 8; threads *= 2) {
      uint8_t actual[BLAKE3_OUT_LEN];
      blake3plus_hash_buffer_mt(buf, len, actual, BLAKE3_OUT_LEN, threads);
      assert(memcmp(expected, actual, BLAKE3_OUT_LEN) == 0);
    }
  }
  free(buf);
}

__attribute__((noinline)) void dummy_sink(void) {
  __asm__ __volatile__("" ::: "memory");
}

__attribute__((noinline)) void test_stack_wipe_dse(const uint8_t *key) {
  blake3_hasher hasher;
  blake3_hasher_init_keyed(&hasher, key);
  blake3plus_hasher_update_mt(&hasher, "secret_payload", 14, 1);
  dummy_sink();
  blake3plus_hasher_secure_wipe(&hasher);
}

static void test_secure_wipe(void) {
  uint8_t key[BLAKE3_KEY_LEN];
  memset(key, 0xAA, sizeof(key));

  test_stack_wipe_dse(key);

  blake3_hasher h;
  blake3_hasher_init_keyed(&h, key);
  uint8_t msg[8192];
  fill_pattern(msg, sizeof(msg));
  blake3_hasher_update(&h, msg, sizeof(msg));

  blake3plus_hasher_secure_wipe(&h);
  const uint8_t *raw = (const uint8_t *)&h;
  for (size_t i = 0; i < sizeof(h); i++) {
    assert(raw[i] == 0);
  }
}

#if (defined(__x86_64__) || defined(__i386__)) && \
    !defined(__SANITIZE_THREAD__) && !defined(__SANITIZE_ADDRESS__)
#define B3P_ENABLE_RDTSC_TEST 1
#endif

#if defined(B3P_ENABLE_RDTSC_TEST)
static inline uint64_t rdtsc_start(void) {
  uint32_t lo, hi;
  __asm__ __volatile__("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) : : "memory");
  return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_end(void) {
  uint32_t lo, hi, aux;
  __asm__ __volatile__("rdtscp\n\tlfence"
                       : "=a"(lo), "=d"(hi), "=c"(aux)
                       :
                       : "memory");
  return ((uint64_t)hi << 32) | lo;
}

static void test_constant_time_welch(const uint8_t *mac_valid) {
  uint8_t cand[64];
  double n0 = 0.0, mean0 = 0.0, m2_0 = 0.0;
  double n1 = 0.0, mean1 = 0.0, m2_1 = 0.0;
  uint64_t rng = 0x853c49e6748fea9bULL;
  const int trials = 100000;

  memcpy(cand, mac_valid, 64);
  for (int i = 0; i < 4000; i++) {
    (void)blake3plus_constant_time_eq(mac_valid, cand, 64);
  }

  for (int i = 0; i < trials; i++) {
    rng ^= rng >> 12;
    rng ^= rng << 25;
    rng ^= rng >> 27;
    int cls = (int)((rng * 0x2545F4914F6CDD1DULL) >> 63);
    memcpy(cand, mac_valid, 64);
    cand[cls ? 63 : 0] ^= 0x01;

    uint64_t t0 = rdtsc_start();
    int rc = blake3plus_constant_time_eq(mac_valid, cand, 64);
    uint64_t dt = rdtsc_end() - t0;
    assert(rc == -1);
    if (dt > 250) {
      continue;
    }
    double x = (double)dt;
    if (cls == 0) {
      n0 += 1.0;
      double d = x - mean0;
      mean0 += d / n0;
      m2_0 += d * (x - mean0);
    } else {
      n1 += 1.0;
      double d = x - mean1;
      mean1 += d / n1;
      m2_1 += d * (x - mean1);
    }
  }

  if (n0 > 1000.0 && n1 > 1000.0) {
    double v0 = m2_0 / (n0 - 1.0);
    double v1 = m2_1 / (n1 - 1.0);
    double se = sqrt(v0 / n0 + v1 / n1);
    if (se > 1e-9) {
      double t_stat = fabs(mean0 - mean1) / se;
      assert(t_stat < 4.5);
    }
  }
}
#endif

static void test_constant_time_mac(void) {
  uint8_t key[BLAKE3_KEY_LEN];
  for (size_t i = 0; i < sizeof(key); i++) {
    key[i] = (uint8_t)(i * 7 + 3);
  }

  size_t len = 256 * 1024 + 19;
  uint8_t *msg = (uint8_t *)malloc(len);
  assert(msg != NULL);
  fill_pattern(msg, len);

  uint8_t mac[64];
  blake3plus_keyed_mac_sign(key, msg, len, mac, sizeof(mac), 4);
  assert(blake3plus_keyed_mac_verify(key, msg, len, mac, sizeof(mac), 4) == 0);

  for (size_t b = 0; b < sizeof(mac); b++) {
    mac[b] ^= 0x01;
    assert(blake3plus_keyed_mac_verify(key, msg, len, mac, sizeof(mac), 4) == -1);
    mac[b] ^= 0x01;
  }

#if defined(B3P_ENABLE_RDTSC_TEST)
  test_constant_time_welch(mac);
#endif

  free(msg);
}

static void test_pool_lifecycle_and_fork(void) {
  blake3plus_pool_teardown();
  assert(blake3plus_get_active_workers() == 0);

  uint8_t buf[256 * 1024];
  fill_pattern(buf, sizeof(buf));
  uint8_t expected[BLAKE3_OUT_LEN];
  blake3plus_hash_buffer_mt(buf, sizeof(buf), expected, sizeof(expected), 1);

  uint8_t out[BLAKE3_OUT_LEN];
  blake3plus_hash_buffer_mt(buf, sizeof(buf), out, sizeof(out), 4);
  assert(memcmp(expected, out, BLAKE3_OUT_LEN) == 0);

  int sync_pipe[2];
  assert(pipe(sync_pipe) == 0);

  enum { NUM_CHILDREN = 32 };
  pid_t pids[NUM_CHILDREN];
  for (int i = 0; i < NUM_CHILDREN; i++) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
      close(sync_pipe[1]);
      char tok = 0;
      ssize_t r = read(sync_pipe[0], &tok, 1);
      (void)r;
      close(sync_pipe[0]);

      if (blake3plus_get_active_workers() != 0) {
        _exit(10);
      }
      uint8_t child_out[BLAKE3_OUT_LEN];
      blake3plus_hash_buffer_mt(buf, sizeof(buf), child_out, sizeof(child_out), 2);
      if (memcmp(expected, child_out, BLAKE3_OUT_LEN) != 0) {
        _exit(11);
      }
      blake3plus_pool_teardown();
      _exit(0);
    }
    pids[i] = pid;
  }

  close(sync_pipe[0]);
  close(sync_pipe[1]);

  for (int i = 0; i < NUM_CHILDREN; i++) {
    int status = 0;
    assert(waitpid(pids[i], &status, 0) == pids[i]);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  blake3plus_pool_teardown();
  assert(blake3plus_get_active_workers() == 0);
}

static int write_str(const char *path, const char *s) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) {
    return -1;
  }
  size_t n = strlen(s);
  ssize_t w = write(fd, s, n);
  close(fd);
  return (w == (ssize_t)n) ? 0 : -1;
}

static void test_cgroup_quotas(void) {
  char tpl[] = "/tmp/b3p_cg_XXXXXX";
  char *dir = mkdtemp(tpl);
  assert(dir != NULL);

  char cpu_max[512];
  snprintf(cpu_max, sizeof(cpu_max), "%s/cpu.max", dir);

  static const struct {
    const char *spec;
    size_t cpus;
    size_t workers;
  } cases[] = {
      {"50000 100000\n", 1, 0},
      {"100000 100000\n", 1, 0},
      {"200000 100000\n", 2, 1},
  };

  uint8_t *buf = (uint8_t *)malloc(256 * 1024);
  assert(buf != NULL);
  fill_pattern(buf, 256 * 1024);
  uint8_t expected[BLAKE3_OUT_LEN];
  blake3plus_hash_buffer_mt(buf, 256 * 1024, expected, BLAKE3_OUT_LEN, 1);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    assert(write_str(cpu_max, cases[i].spec) == 0);
    setenv("BLAKE3PLUS_CGROUP_ROOT", dir, 1);
    blake3plus_pool_teardown();

    assert(blake3plus_detect_cgroup_cpu_quota() == cases[i].cpus);
    assert(blake3plus_get_effective_cpus() == cases[i].cpus);

    uint8_t out[BLAKE3_OUT_LEN];
    blake3plus_hash_buffer_mt(buf, 256 * 1024, out, BLAKE3_OUT_LEN, 32);
    assert(memcmp(expected, out, BLAKE3_OUT_LEN) == 0);
    assert(blake3plus_get_active_workers() == cases[i].workers);
  }

  unsetenv("BLAKE3PLUS_CGROUP_ROOT");
  blake3plus_pool_teardown();
  unlink(cpu_max);
  rmdir(dir);
  free(buf);
}

static void test_file_mmap_and_fifo_fallback(void) {
  size_t len = 512 * 1024 + 7;
  uint8_t *buf = (uint8_t *)malloc(len);
  assert(buf != NULL);
  fill_pattern(buf, len);

  uint8_t expected[BLAKE3_OUT_LEN];
  blake3plus_hash_buffer_mt(buf, len, expected, sizeof(expected), 2);

  char tmp_file[] = "/tmp/b3p_test_XXXXXX";
  int fd = mkstemp(tmp_file);
  assert(fd >= 0);
  size_t written = 0;
  while (written < len) {
    ssize_t n = write(fd, buf + written, len - written);
    assert(n > 0);
    written += (size_t)n;
  }
  close(fd);

  uint8_t file_out[BLAKE3_OUT_LEN];
  assert(blake3plus_hash_file_mmap(tmp_file, file_out, sizeof(file_out), 0) == 0);
  assert(memcmp(expected, file_out, BLAKE3_OUT_LEN) == 0);

  int fd_ro = open(tmp_file, O_RDONLY | O_CLOEXEC);
  assert(fd_ro >= 0);
  uint8_t fd_out[BLAKE3_OUT_LEN];
  assert(blake3plus_hash_fd(fd_ro, fd_out, sizeof(fd_out), 2) == 0);
  close(fd_ro);
  assert(memcmp(expected, fd_out, BLAKE3_OUT_LEN) == 0);
  unlink(tmp_file);

  char fifo_path[128];
  snprintf(fifo_path, sizeof(fifo_path), "/tmp/b3p_fifo_%d", (int)getpid());
  unlink(fifo_path);
  assert(mkfifo(fifo_path, 0600) == 0);

  pid_t writer = fork();
  assert(writer >= 0);
  if (writer == 0) {
    int wfd = open(fifo_path, O_WRONLY);
    if (wfd < 0) _exit(1);
    size_t w = 0;
    while (w < len) {
      ssize_t n = write(wfd, buf + w, len - w);
      if (n <= 0) _exit(1);
      w += (size_t)n;
    }
    close(wfd);
    _exit(0);
  }

  uint8_t fifo_out[BLAKE3_OUT_LEN];
  assert(blake3plus_hash_file_mmap(fifo_path, fifo_out, sizeof(fifo_out), 0) == 0);
  int st = 0;
  waitpid(writer, &st, 0);
  unlink(fifo_path);
  assert(memcmp(expected, fifo_out, BLAKE3_OUT_LEN) == 0);
  free(buf);
}

static double now_sec(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void run_bench(void) {
  size_t len = 64 * 1024 * 1024;
  int iters = 16;
  uint8_t *buf = (uint8_t *)malloc(len);
  assert(buf != NULL);
  fill_pattern(buf, len);
  uint8_t out[BLAKE3_OUT_LEN];

  size_t hw = blake3plus_get_effective_cpus();
  blake3plus_hash_buffer_mt(buf, len, out, sizeof(out), hw);

  size_t thread_counts[] = {1, 2, 4, 6, 8, 12};
  double dt_1t = 0.0;
  for (size_t idx = 0; idx < sizeof(thread_counts) / sizeof(thread_counts[0]); idx++) {
    size_t t = thread_counts[idx];
    if (t > hw && idx > 0) {
      continue;
    }
    blake3plus_hash_buffer_mt(buf, len, out, sizeof(out), t);
    double t0 = now_sec();
    for (int i = 0; i < iters; i++) {
      blake3plus_hash_buffer_mt(buf, len, out, sizeof(out), t);
    }
    double dt = now_sec() - t0;
    if (t == 1) {
      dt_1t = dt;
    }
    printf("c11 1 GiB (64 MiB x 16) %2zuT: %6.2f GB/s (%5.2fx)\n",
           t, 1.073741824 / dt, dt_1t / dt);
  }
  free(buf);
  blake3plus_pool_teardown();
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "--bench") == 0) {
    run_bench();
    return 0;
  }
  test_unaligned_subtrees();
  test_secure_wipe();
  test_constant_time_mac();
  test_pool_lifecycle_and_fork();
  test_cgroup_quotas();
  test_file_mmap_and_fifo_fallback();
  printf("c/test_mt: ok\n");
  return 0;
}
