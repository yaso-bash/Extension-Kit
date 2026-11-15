CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CC32 = i686-w64-mingw32-gcc
STRIP32 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ./src/common -w -Wno-incompatible-pointer-types -Os -s -DBOF -c

all: bof

bof:
	@(mkdir -p _bin/SQL 2>/dev/null) && echo 'creating _bin/SQL' || echo '_bin/SQL exists'
	@($(CC64) $(CFLAGS) src/SQL/1434udp/entry.c -o _bin/SQL/1434udp.x64.o       && $(STRIP64) _bin/SQL/1434udp.x64.o) && echo '[+] 1434udp' || echo '[!] 1434udp'
	@($(CC32) $(CFLAGS) src/SQL/1434udp/entry.c -o _bin/SQL/1434udp.x32.o       && $(STRIP32) _bin/SQL/1434udp.x32.o) && echo '[+] 1434udp x32' || echo '[!] 1434udp x32'
	@($(CC64) $(CFLAGS) src/SQL/adsi/entry.c -o _bin/SQL/adsi.x64.o             && $(STRIP64) _bin/SQL/adsi.x64.o) && echo '[+] adsi' || echo '[!] adsi'
	@($(CC32) $(CFLAGS) src/SQL/adsi/entry.c -o _bin/SQL/adsi.x32.o             && $(STRIP32) _bin/SQL/adsi.x32.o) && echo '[+] adsi x32' || echo '[!] adsi x32'
	@($(CC64) $(CFLAGS) src/SQL/agentcmd/entry.c -o _bin/SQL/agentcmd.x64.o     && $(STRIP64) _bin/SQL/agentcmd.x64.o) && echo '[+] agentcmd' || echo '[!] agentcmd'
	@($(CC32) $(CFLAGS) src/SQL/agentcmd/entry.c -o _bin/SQL/agentcmd.x32.o     && $(STRIP32) _bin/SQL/agentcmd.x32.o) && echo '[+] agentcmd x32' || echo '[!] agentcmd x32'
	@($(CC64) $(CFLAGS) src/SQL/agentstatus/entry.c -o _bin/SQL/agentstatus.x64.o && $(STRIP64) _bin/SQL/agentstatus.x64.o) && echo '[+] agentstatus' || echo '[!] agentstatus'
	@($(CC32) $(CFLAGS) src/SQL/agentstatus/entry.c -o _bin/SQL/agentstatus.x32.o && $(STRIP32) _bin/SQL/agentstatus.x32.o) && echo '[+] agentstatus x32' || echo '[!] agentstatus x32'
	@($(CC64) $(CFLAGS) src/SQL/checkrpc/entry.c -o _bin/SQL/checkrpc.x64.o     && $(STRIP64) _bin/SQL/checkrpc.x64.o) && echo '[+] checkrpc' || echo '[!] checkrpc'
	@($(CC32) $(CFLAGS) src/SQL/checkrpc/entry.c -o _bin/SQL/checkrpc.x32.o     && $(STRIP32) _bin/SQL/checkrpc.x32.o) && echo '[+] checkrpc x32' || echo '[!] checkrpc x32'
	@($(CC64) $(CFLAGS) src/SQL/clr/entry.c -o _bin/SQL/clr.x64.o               && $(STRIP64) _bin/SQL/clr.x64.o) && echo '[+] clr' || echo '[!] clr'
	@($(CC32) $(CFLAGS) src/SQL/clr/entry.c -o _bin/SQL/clr.x32.o               && $(STRIP32) _bin/SQL/clr.x32.o) && echo '[+] clr x32' || echo '[!] clr x32'
	@($(CC64) $(CFLAGS) src/SQL/columns/entry.c -o _bin/SQL/columns.x64.o       && $(STRIP64) _bin/SQL/columns.x64.o) && echo '[+] columns' || echo '[!] columns'
	@($(CC32) $(CFLAGS) src/SQL/columns/entry.c -o _bin/SQL/columns.x32.o       && $(STRIP32) _bin/SQL/columns.x32.o) && echo '[+] columns x32' || echo '[!] columns x32'
	@($(CC64) $(CFLAGS) src/SQL/databases/entry.c -o _bin/SQL/databases.x64.o   && $(STRIP64) _bin/SQL/databases.x64.o) && echo '[+] databases' || echo '[!] databases'
	@($(CC32) $(CFLAGS) src/SQL/databases/entry.c -o _bin/SQL/databases.x32.o   && $(STRIP32) _bin/SQL/databases.x32.o) && echo '[+] databases x32' || echo '[!] databases x32'
	@($(CC64) $(CFLAGS) src/SQL/togglemodule/entry.c -o _bin/SQL/togglemodule.x64.o && $(STRIP64) _bin/SQL/togglemodule.x64.o) && echo '[+] togglemodule' || echo '[!] togglemodule'
	@($(CC32) $(CFLAGS) src/SQL/togglemodule/entry.c -o _bin/SQL/togglemodule.x32.o && $(STRIP32) _bin/SQL/togglemodule.x32.o) && echo '[+] togglemodule x32' || echo '[!] togglemodule x32'
	@($(CC64) $(CFLAGS) src/SQL/impersonate/entry.c -o _bin/SQL/impersonate.x64.o && $(STRIP64) _bin/SQL/impersonate.x64.o) && echo '[+] impersonate' || echo '[!] impersonate'
	@($(CC32) $(CFLAGS) src/SQL/impersonate/entry.c -o _bin/SQL/impersonate.x32.o && $(STRIP32) _bin/SQL/impersonate.x32.o) && echo '[+] impersonate x32' || echo '[!] impersonate x32'
	@($(CC64) $(CFLAGS) src/SQL/info/entry.c -o _bin/SQL/info.x64.o             && $(STRIP64) _bin/SQL/info.x64.o) && echo '[+] info' || echo '[!] info'
	@($(CC32) $(CFLAGS) src/SQL/info/entry.c -o _bin/SQL/info.x32.o             && $(STRIP32) _bin/SQL/info.x32.o) && echo '[+] info x32' || echo '[!] info x32'
	@($(CC64) $(CFLAGS) src/SQL/links/entry.c -o _bin/SQL/links.x64.o           && $(STRIP64) _bin/SQL/links.x64.o) && echo '[+] links' || echo '[!] links'
	@($(CC32) $(CFLAGS) src/SQL/links/entry.c -o _bin/SQL/links.x32.o           && $(STRIP32) _bin/SQL/links.x32.o) && echo '[+] links x32' || echo '[!] links x32'
	@($(CC64) $(CFLAGS) src/SQL/olecmd/entry.c -o _bin/SQL/olecmd.x64.o         && $(STRIP64) _bin/SQL/olecmd.x64.o) && echo '[+] olecmd' || echo '[!] olecmd'
	@($(CC32) $(CFLAGS) src/SQL/olecmd/entry.c -o _bin/SQL/olecmd.x32.o         && $(STRIP32) _bin/SQL/olecmd.x32.o) && echo '[+] olecmd x32' || echo '[!] olecmd x32'
	@($(CC64) $(CFLAGS) src/SQL/query/entry.c -o _bin/SQL/query.x64.o           && $(STRIP64) _bin/SQL/query.x64.o) && echo '[+] query' || echo '[!] query'
	@($(CC32) $(CFLAGS) src/SQL/query/entry.c -o _bin/SQL/query.x32.o           && $(STRIP32) _bin/SQL/query.x32.o) && echo '[+] query x32' || echo '[!] query x32'
	@($(CC64) $(CFLAGS) src/SQL/rows/entry.c -o _bin/SQL/rows.x64.o             && $(STRIP64) _bin/SQL/rows.x64.o) && echo '[+] rows' || echo '[!] rows'
	@($(CC32) $(CFLAGS) src/SQL/rows/entry.c -o _bin/SQL/rows.x32.o             && $(STRIP32) _bin/SQL/rows.x32.o) && echo '[+] rows x32' || echo '[!] rows x32'
	@($(CC64) $(CFLAGS) src/SQL/search/entry.c -o _bin/SQL/search.x64.o         && $(STRIP64) _bin/SQL/search.x64.o) && echo '[+] search' || echo '[!] search'
	@($(CC32) $(CFLAGS) src/SQL/search/entry.c -o _bin/SQL/search.x32.o         && $(STRIP32) _bin/SQL/search.x32.o) && echo '[+] search x32' || echo '[!] search x32'
	@($(CC64) $(CFLAGS) src/SQL/smb/entry.c -o _bin/SQL/smb.x64.o               && $(STRIP64) _bin/SQL/smb.x64.o) && echo '[+] smb' || echo '[!] smb'
	@($(CC32) $(CFLAGS) src/SQL/smb/entry.c -o _bin/SQL/smb.x32.o               && $(STRIP32) _bin/SQL/smb.x32.o) && echo '[+] smb x32' || echo '[!] smb x32'
	@($(CC64) $(CFLAGS) src/SQL/tables/entry.c -o _bin/SQL/tables.x64.o         && $(STRIP64) _bin/SQL/tables.x64.o) && echo '[+] tables' || echo '[!] tables'
	@($(CC32) $(CFLAGS) src/SQL/tables/entry.c -o _bin/SQL/tables.x32.o         && $(STRIP32) _bin/SQL/tables.x32.o) && echo '[+] tables x32' || echo '[!] tables x32'
	@($(CC64) $(CFLAGS) src/SQL/users/entry.c -o _bin/SQL/users.x64.o           && $(STRIP64) _bin/SQL/users.x64.o) && echo '[+] users' || echo '[!] users'
	@($(CC32) $(CFLAGS) src/SQL/users/entry.c -o _bin/SQL/users.x32.o           && $(STRIP32) _bin/SQL/users.x32.o) && echo '[+] users x32' || echo '[!] users x32'
	@($(CC64) $(CFLAGS) src/SQL/whoami/entry.c -o _bin/SQL/whoami.x64.o         && $(STRIP64) _bin/SQL/whoami.x64.o) && echo '[+] whoami' || echo '[!] whoami'
	@($(CC32) $(CFLAGS) src/SQL/whoami/entry.c -o _bin/SQL/whoami.x32.o         && $(STRIP32) _bin/SQL/whoami.x32.o) && echo '[+] whoami x32' || echo '[!] whoami x32'
	@($(CC64) $(CFLAGS) src/SQL/xpcmd/entry.c -o _bin/SQL/xpcmd.x64.o           && $(STRIP64) _bin/SQL/xpcmd.x64.o) && echo '[+] xpcmd' || echo '[!] xpcmd'
	@($(CC32) $(CFLAGS) src/SQL/xpcmd/entry.c -o _bin/SQL/xpcmd.x32.o           && $(STRIP32) _bin/SQL/xpcmd.x32.o) && echo '[+] xpcmd x32' || echo '[!] xpcmd x32'

clean:
	@(rm -rf _bin)
