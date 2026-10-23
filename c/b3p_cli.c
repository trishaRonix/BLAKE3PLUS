#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake3plus.h"

static void print_hex(const uint8_t *bytes, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", bytes[i]);
  }
}

static int parse_hex(const char *hex, uint8_t *out, size_t expected_bytes) {
  size_t len = strlen(hex);
  if (len != expected_bytes * 2) {
    return -1;
  }
  for (size_t i = 0; i < expected_bytes; i++) {
    char c1 = hex[i * 2];
    char c2 = hex[i * 2 + 1];
    if (!isxdigit((unsigned char)c1) || !isxdigit((unsigned char)c2)) {
      return -1;
    }
    int v1 = (c1 >= '0' && c1 <= '9') ? (c1 - '0') : ((c1 >= 'a' && c1 <= 'f') ? (c1 - 'a' + 10) : (c1 - 'A' + 10));
    int v2 = (c2 >= '0' && c2 <= '9') ? (c2 - '0') : ((c2 >= 'a' && c2 <= 'f') ? (c2 - 'a' + 10) : (c2 - 'A' + 10));
    out[i] = (uint8_t)((v1 << 4) | v2);
  }
  return 0;
}

static void print_usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [OPTIONS] [FILE...]\n\n"
          "Options:\n"
          "  --threads N         Maximum number of threads (default: %zu)\n"
          "  --length N          Output length in bytes (default: 32)\n"
          "  --keyed HEX_KEY     64-char hex key for keyed hashing\n"
          "  --verify-mac HEX    Verify against expected hex digest in constant time\n"
          "  --derive-key CTX    Key derivation context string\n"
          "  --help              Print help\n",
          prog, blake3plus_get_hw_threads());
}

int main(int argc, char **argv) {
  size_t threads = 0;
  size_t out_len = BLAKE3_OUT_LEN;
  bool use_keyed = false;
  uint8_t key[BLAKE3_KEY_LEN];
  const char *derive_ctx = NULL;
  const char *verify_mac_hex = NULL;

  int arg_idx = 1;
  while (arg_idx < argc && strncmp(argv[arg_idx], "--", 2) == 0) {
    const char *opt = argv[arg_idx];
    if (strcmp(opt, "--help") == 0) {
      print_usage(argv[0]);
      return 0;
    } else if (strcmp(opt, "--threads") == 0 && arg_idx + 1 < argc) {
      threads = (size_t)strtoull(argv[arg_idx + 1], NULL, 10);
      arg_idx += 2;
    } else if (strcmp(opt, "--length") == 0 && arg_idx + 1 < argc) {
      out_len = (size_t)strtoull(argv[arg_idx + 1], NULL, 10);
      if (out_len == 0 || out_len > 1024 * 1024) {
        fprintf(stderr, "b3p: invalid --length value\n");
        return 1;
      }
      arg_idx += 2;
    } else if (strcmp(opt, "--keyed") == 0 && arg_idx + 1 < argc) {
      if (parse_hex(argv[arg_idx + 1], key, BLAKE3_KEY_LEN) != 0) {
        fprintf(stderr, "b3p: --keyed requires a 64-character hex string\n");
        return 1;
      }
      use_keyed = true;
      arg_idx += 2;
    } else if (strcmp(opt, "--verify-mac") == 0 && arg_idx + 1 < argc) {
      verify_mac_hex = argv[arg_idx + 1];
      arg_idx += 2;
    } else if (strcmp(opt, "--derive-key") == 0 && arg_idx + 1 < argc) {
      derive_ctx = argv[arg_idx + 1];
      arg_idx += 2;
    } else {
      fprintf(stderr, "b3p: unrecognized option '%s'\n", opt);
      print_usage(argv[0]);
      return 1;
    }
  }

  uint8_t *out = (uint8_t *)malloc(out_len);
  if (!out) {
    perror("malloc");
    return 1;
  }

  int num_files = argc - arg_idx;
  const char *default_stdin[] = {"/dev/stdin"};
  const char **files =
      (num_files > 0) ? (const char **)&argv[arg_idx] : default_stdin;
  if (num_files == 0) {
    num_files = 1;
  }

  int exit_code = 0;
  for (int i = 0; i < num_files; i++) {
    const char *path = files[i];
    if (!use_keyed && !derive_ctx) {
      if (blake3plus_hash_file_mmap(path, out, out_len, threads) != 0) {
        fprintf(stderr, "b3p: %s: %s\n", path, strerror(errno));
        exit_code = 1;
        continue;
      }
    } else {
      FILE *fp = (strcmp(path, "/dev/stdin") == 0) ? stdin : fopen(path, "rb");
      if (!fp) {
        fprintf(stderr, "b3p: %s: %s\n", path, strerror(errno));
        exit_code = 1;
        continue;
      }
      blake3_hasher hasher;
      if (use_keyed) {
        blake3_hasher_init_keyed(&hasher, key);
      } else {
        blake3_hasher_init_derive_key(&hasher, derive_ctx);
      }
      size_t buf_sz = 4 * 1024 * 1024;
      uint8_t *buf = (uint8_t *)malloc(buf_sz);
      if (!buf) {
        fprintf(stderr, "b3p: malloc failed\n");
        blake3plus_hasher_secure_wipe(&hasher);
        if (fp != stdin) {
          fclose(fp);
        }
        exit_code = 1;
        break;
      }
      size_t n;
      while ((n = fread(buf, 1, buf_sz, fp)) > 0) {
        blake3plus_hasher_update_mt(&hasher, buf, n, threads);
      }
      if (ferror(fp)) {
        fprintf(stderr, "b3p: %s: read error\n", path);
        blake3plus_hasher_secure_wipe(&hasher);
        blake3plus_secure_zero(buf, buf_sz);
        free(buf);
        if (fp != stdin) {
          fclose(fp);
        }
        exit_code = 1;
        continue;
      }
      blake3_hasher_finalize(&hasher, out, out_len);
      blake3plus_hasher_secure_wipe(&hasher);
      blake3plus_secure_zero(buf, buf_sz);
      free(buf);
      if (fp != stdin) {
        fclose(fp);
      }
    }

    if (verify_mac_hex) {
      uint8_t *expected = (uint8_t *)malloc(out_len);
      if (!expected || parse_hex(verify_mac_hex, expected, out_len) != 0) {
        fprintf(stderr, "b3p: invalid --verify-mac hex string\n");
        free(expected);
        exit_code = 1;
        break;
      }
      int ok = blake3plus_constant_time_eq(out, expected, out_len);
      blake3plus_secure_zero(expected, out_len);
      free(expected);
      if (ok == 0) {
        printf("%s: OK\n", path);
      } else {
        fprintf(stderr, "%s: FAILED\n", path);
        exit_code = 2;
      }
    } else {
      print_hex(out, out_len);
      if (num_files > 1 || strcmp(path, "/dev/stdin") != 0) {
        printf("  %s", path);
      }
      printf("\n");
    }
  }

  blake3plus_secure_zero(key, sizeof(key));
  blake3plus_secure_zero(out, out_len);
  free(out);
  return exit_code;
}
