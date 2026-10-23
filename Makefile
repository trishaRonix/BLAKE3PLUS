export PATH := $(HOME)/.cargo/bin:$(PATH)

CC       ?= gcc
CFLAGS   ?= -O3 -march=native -Wall -Wextra -Werror -pthread -DBLAKE3PLUS_ENABLE_PTHREAD
ASAN_FLAGS ?= -O2 -g -Wall -Wextra -Werror -pthread -fsanitize=address,undefined -fno-sanitize-recover=all -DBLAKE3PLUS_ENABLE_PTHREAD
TSAN_FLAGS ?= -O2 -g -Wall -Wextra -Werror -pthread -fsanitize=thread -no-pie -fno-pie -DBLAKE3PLUS_ENABLE_PTHREAD

C_SRC    := c/blake3plus.c c/blake3.c c/blake3_dispatch.c c/blake3_portable.c
C_ASM    := c/blake3_sse2_x86-64_unix.S c/blake3_sse41_x86-64_unix.S \
            c/blake3_avx2_x86-64_unix.S c/blake3_avx512_x86-64_unix.S

CARGO    ?= cargo

.PHONY: all test bench clean

all: c/b3p
	$(CARGO) build --release --manifest-path b3sum/Cargo.toml

c/b3p: c/b3p_cli.c c/blake3plus.h $(C_SRC) $(C_ASM)
	$(CC) $(CFLAGS) c/b3p_cli.c $(C_SRC) $(C_ASM) -o c/b3p

test: c/b3p
	$(CC) $(CFLAGS) c/test_mt.c $(C_SRC) $(C_ASM) -lm -o c/test_mt
	./c/test_mt
	$(CC) $(ASAN_FLAGS) c/test_mt.c $(C_SRC) $(C_ASM) -lm -o c/test_mt
	ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1" ./c/test_mt
	$(CC) $(TSAN_FLAGS) c/test_mt.c $(C_SRC) $(C_ASM) -lm -o c/test_mt
	TSAN_OPTIONS="die_after_fork=0:halt_on_error=1" setarch x86_64 -R ./c/test_mt
	@rm -f c/test_mt
	$(CARGO) test --features "rayon mmap zeroize"
	$(CARGO) test --manifest-path b3sum/Cargo.toml

bench:
	$(CC) $(CFLAGS) c/test_mt.c $(C_SRC) $(C_ASM) -lm -o c/test_mt
	./c/test_mt --bench
	@rm -f c/test_mt

clean:
	rm -f c/b3p c/test_mt c/*.o
	$(CARGO) clean
	$(CARGO) clean --manifest-path b3sum/Cargo.toml
