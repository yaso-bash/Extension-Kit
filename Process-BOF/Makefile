CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CC32 = i686-w64-mingw32-gcc
STRIP32 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -masm=intel -w -Wno-incompatible-pointer-types -Os -DBOF -c
CFLAGS32 = $(CFLAGS) -DWOW64

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) findobjects/FindModule.c -o _bin/findmodule.x64.o && $(STRIP64) _bin/findmodule.x64.o) && echo '[+] findmodule' || echo '[!] findmodule'
	@($(CC32) $(CFLAGS32) findobjects/FindModule.c -o _bin/findmodule.x32.o && $(STRIP32) _bin/findmodule.x32.o) && echo '[+] findmodule x32' || echo '[!] findmodule x32'
	@($(CC64) $(CFLAGS) findobjects/FindProcHandle.c -o _bin/findprochandle.x64.o && $(STRIP64) _bin/findprochandle.x64.o) && echo '[+] findprochandle' || echo '[!] findprochandle'
	@($(CC32) $(CFLAGS32) findobjects/FindProcHandle.c -o _bin/findprochandle.x32.o && $(STRIP32) _bin/findprochandle.x32.o) && echo '[+] findprochandle x32' || echo '[!] findprochandle x32'
	@($(CC64) $(CFLAGS) process/psc.c -o _bin/psc.x64.o && $(STRIP64) _bin/psc.x64.o) && echo '[+] psc' || echo '[!] psc'
	@($(CC32) $(CFLAGS32) process/psc.c -o _bin/psc.x32.o && $(STRIP32) _bin/psc.x32.o) && echo '[+] psc x32' || echo '[!] psc x32'
	@($(CC64) $(CFLAGS) procfreeze/procfreeze.c -o _bin/procfreeze.x64.o && $(STRIP64) _bin/procfreeze.x64.o) && echo '[+] procfreeze' || echo '[!] procfreeze'
	@($(CC32) $(CFLAGS32) procfreeze/procfreeze.c -o _bin/procfreeze.x32.o && $(STRIP32) _bin/procfreeze.x32.o) && echo '[+] procfreeze x32' || echo '[!] procfreeze x32'

clean:
	@(rm -rf _bin)
