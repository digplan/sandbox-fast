CC      := clang
CFLAGS  := -std=c11 -O3 -flto -mcpu=native -Wall -Wextra -Werror -Wno-deprecated-declarations
LDFLAGS := -lsandbox -flto

.PHONY: all bench verify test1000 clean

all: sbx bench_bin test_1000

sbx: main.c sbx.c bench.c sbx.h
	$(CC) $(CFLAGS) main.c sbx.c bench.c $(LDFLAGS) -o sbx

bench_bin: bench.c sbx.c sbx.h
	$(CC) $(CFLAGS) -DSBX_STANDALONE_BENCH bench.c sbx.c $(LDFLAGS) -o bench

test_1000: test_1000.c sbx.c sbx.h
	$(CC) $(CFLAGS) test_1000.c sbx.c $(LDFLAGS) -o test_1000

test1000: test_1000
	./test_1000.sh

bench: sbx
	./sbx bench

verify: sbx
	./sbx verify

clean:
	-./sbx daemon stop >/dev/null 2>&1 || true
	rm -f sbx bench test_1000
	rm -rf /private/tmp/sbx-fast
