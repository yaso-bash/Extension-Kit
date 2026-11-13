all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[!] _bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -fno-builtin -s -I No-Consolation/include -c -o _bin/execute-assembly.x64.o execute-assembly/inlineExecute-Assembly.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/execute-assembly.x64.o) && echo '[+] execute-assembly' || echo '[!] execute-assembly build failed'

	@(x86_64-w64-mingw32-gcc -Os -fno-builtin -mno-stack-arg-probe -nostdlib -e _start -s -o hollow/dotnet_host.exe hollow/dotnet_host.c -lkernel32 && python3 -c "import sys;d=open('hollow/dotnet_host.exe','rb').read();f=open('hollow/dotnet_host_bytes.h','w');f.write('#ifndef DOTNET_HOST_BYTES_H\n#define DOTNET_HOST_BYTES_H\nstatic unsigned char dotnet_host_exe[] = {\n');f.write(','.join(['0x%02x'%b for b in d]));f.write('\n};\nstatic unsigned int dotnet_host_exe_len = %d;\n#endif\n'%len(d));f.close()") && echo '[+] dotnet_host' || echo '[!] dotnet_host build failed'

	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -fno-builtin -mno-stack-arg-probe -s -I No-Consolation/include -I hollow -c -o _bin/hollow.x64.o hollow/hollow.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/hollow.x64.o) && echo '[+] hollow' || echo '[!] hollow build failed'

	@$(MAKE) --no-print-directory -C No-Consolation
	@cp No-Consolation/_bin/*.o _bin/


clean:
	@(rm -rf _bin)