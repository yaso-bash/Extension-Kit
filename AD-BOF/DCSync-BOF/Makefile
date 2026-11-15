CC = x86_64-w64-mingw32-gcc
LD = x86_64-w64-mingw32-ld
STRIP = x86_64-w64-mingw32-strip

CC32 = i686-w64-mingw32-gcc
LD32 = i686-w64-mingw32-ld
STRIP32 = i686-w64-mingw32-strip

CFLAGS_BASE = -I. -Os -masm=intel -fno-stack-protector -mno-stack-arg-probe -DBOF -Wall -Wno-format -Wno-unused-variable -Wno-unknown-pragmas -Wno-missing-braces -Wno-builtin-macro-redefined
CFLAGS_RELEASE = $(CFLAGS_BASE) -DNDEBUG
CFLAGS_RELEASE_64 = $(CFLAGS_RELEASE) -D_M_AMD64
LDFLAGS = -r

CFLAGS = $(CFLAGS_RELEASE_64)
RPC_STUB = drsuapi/ms-drsr-custom.c

all: both

both: clean single-user all-users single-user-x86 all-users-x86

single-user: CFLAGS = $(CFLAGS_RELEASE_64)
single-user: RPC_STUB = drsuapi/ms-drsr-custom.c
single-user: SRC_FILE = src/dcsync-single.c
single-user: bof-single
	@echo '[+] dcsync single'

all-users: CFLAGS = $(CFLAGS_RELEASE_64)
all-users: RPC_STUB = drsuapi/ms-drsr-custom.c
all-users: SRC_FILE = src/dcsync-all.c
all-users: bof-all
	@echo '[+] dcsync all'

single-user-x86: CFLAGS = $(CFLAGS_RELEASE)
single-user-x86: RPC_STUB = drsuapi/ms-drsr-custom.c
single-user-x86: SRC_FILE = src/dcsync-single.c
single-user-x86: bof-single-x86
	@echo '[+] dcsync single x32'

all-users-x86: CFLAGS = $(CFLAGS_RELEASE)
all-users-x86: RPC_STUB = drsuapi/ms-drsr-custom.c
all-users-x86: SRC_FILE = src/dcsync-all.c
all-users-x86: bof-all-x86
	@echo '[+] dcsync all x32'

bof-single:
	@[ -d "_bin" ] || { mkdir -p "_bin"; }
	@$(CC) $(CFLAGS) -c util/rpc-adapter.c -o _bin/rpc-adapter-single.o
	@$(CC) $(CFLAGS) -c $(RPC_STUB) -o _bin/ms-drsr_c-single.o
	@$(CC) $(CFLAGS) -c $(SRC_FILE) -o _bin/dcsync-single-temp.o
	@$(LD) $(LDFLAGS) _bin/rpc-adapter-single.o _bin/ms-drsr_c-single.o _bin/dcsync-single-temp.o -o _bin/dcsync-single.x64.o
	@$(STRIP) --strip-unneeded _bin/dcsync-single.x64.o
	@rm -f _bin/rpc-adapter-single.o _bin/ms-drsr_c-single.o _bin/dcsync-single-temp.o

bof-all:
	@[ -d "_bin" ] || { mkdir -p "_bin"; }
	@$(CC) $(CFLAGS) -c util/rpc-adapter.c -o _bin/rpc-adapter-all.o
	@$(CC) $(CFLAGS) -c $(RPC_STUB) -o _bin/ms-drsr_c-all.o
	@$(CC) $(CFLAGS) -c $(SRC_FILE) -o _bin/dcsync-all-temp.o
	@$(LD) $(LDFLAGS) _bin/rpc-adapter-all.o _bin/ms-drsr_c-all.o _bin/dcsync-all-temp.o -o _bin/dcsync-all.x64.o
	@$(STRIP) --strip-unneeded _bin/dcsync-all.x64.o
	@rm -f _bin/rpc-adapter-all.o _bin/ms-drsr_c-all.o _bin/dcsync-all-temp.o

bof-single-x86:
	@[ -d "_bin" ] || { mkdir -p "_bin"; }
	@$(CC32) $(CFLAGS) -c util/rpc-adapter.c -o _bin/rpc-adapter-single-x86.o
	@$(CC32) $(CFLAGS) -c $(RPC_STUB) -o _bin/ms-drsr_c-single-x86.o
	@$(CC32) $(CFLAGS) -c $(SRC_FILE) -o _bin/dcsync-single-temp-x86.o
	@$(LD32) $(LDFLAGS) _bin/rpc-adapter-single-x86.o _bin/ms-drsr_c-single-x86.o _bin/dcsync-single-temp-x86.o -o _bin/dcsync-single.x32.o
	@$(STRIP32) --strip-unneeded _bin/dcsync-single.x32.o
	@rm -f _bin/rpc-adapter-single-x86.o _bin/ms-drsr_c-single-x86.o _bin/dcsync-single-temp-x86.o

bof-all-x86:
	@[ -d "_bin" ] || { mkdir -p "_bin"; }
	@$(CC32) $(CFLAGS) -c util/rpc-adapter.c -o _bin/rpc-adapter-all-x86.o
	@$(CC32) $(CFLAGS) -c $(RPC_STUB) -o _bin/ms-drsr_c-all-x86.o
	@$(CC32) $(CFLAGS) -c $(SRC_FILE) -o _bin/dcsync-all-temp-x86.o
	@$(LD32) $(LDFLAGS) _bin/rpc-adapter-all-x86.o _bin/ms-drsr_c-all-x86.o _bin/dcsync-all-temp-x86.o -o _bin/dcsync-all.x32.o
	@$(STRIP32) --strip-unneeded _bin/dcsync-all.x32.o
	@rm -f _bin/rpc-adapter-all-x86.o _bin/ms-drsr_c-all-x86.o _bin/dcsync-all-temp-x86.o

clean:
	@rm -rf _bin
