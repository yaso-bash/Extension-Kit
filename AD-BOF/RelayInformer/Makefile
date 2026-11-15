CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CC32 = i686-w64-mingw32-gcc
STRIP32 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I common -w -Wno-incompatible-pointer-types -Os -s -DBOF -c

all: bof

bof:
	@(mkdir -p _bin/RelayInformer 2>/dev/null) && echo 'creating _bin/RelayInformer' || echo '_bin/RelayInformer exists'
	@($(CC64) $(CFLAGS) -lws2_32 relay-informer-smb/entry.c -o _bin/RelayInformer/smb.x64.o   && $(STRIP64) _bin/RelayInformer/smb.x64.o) && echo '[+] relay-informer-smb' || echo '[!] relay-informer-smb'
	@($(CC32) $(CFLAGS) -lws2_32 relay-informer-smb/entry.c -o _bin/RelayInformer/smb.x32.o   && $(STRIP32) _bin/RelayInformer/smb.x32.o) && echo '[+] relay-informer-smb x32' || echo '[!] relay-informer-smb x32'
	@($(CC64) $(CFLAGS) -lodbc32 -lws2_32 relay-informer-mssql/entry.c -o _bin/RelayInformer/mssql.x64.o   && $(STRIP64) _bin/RelayInformer/mssql.x64.o) && echo '[+] relay-informer-mssql' || echo '[!] relay-informer-mssql'
	@($(CC32) $(CFLAGS) -lodbc32 -lws2_32 relay-informer-mssql/entry.c -o _bin/RelayInformer/mssql.x32.o   && $(STRIP32) _bin/RelayInformer/mssql.x32.o) && echo '[+] relay-informer-mssql x32' || echo '[!] relay-informer-mssql x32'
	@($(CC64) $(CFLAGS) -lsecur32 -lwinhttp -lcrypt32 -lbcrypt relay-informer-http/entry.c -o _bin/RelayInformer/http.x64.o   && $(STRIP64) _bin/RelayInformer/http.x64.o) && echo '[+] relay-informer-http' || echo '[!] relay-informer-http'
	@($(CC32) $(CFLAGS) -lsecur32 -lwinhttp -lcrypt32 -lbcrypt relay-informer-http/entry.c -o _bin/RelayInformer/http.x32.o   && $(STRIP32) _bin/RelayInformer/http.x32.o) && echo '[+] relay-informer-http x32' || echo '[!] relay-informer-http x32'
	@($(CC64) $(CFLAGS) -lwldap32 -ldnsapi relay-informer-ldap/entry.c -o _bin/RelayInformer/ldap.x64.o   && $(STRIP64) _bin/RelayInformer/ldap.x64.o) && echo '[+] relay-informer-ldap' || echo '[!] relay-informer-ldap'
	@($(CC32) $(CFLAGS) -lwldap32 -ldnsapi relay-informer-ldap/entry.c -o _bin/RelayInformer/ldap.x32.o   && $(STRIP32) _bin/RelayInformer/ldap.x32.o) && echo '[+] relay-informer-ldap x32' || echo '[!] relay-informer-ldap x32'

clean:
	@(rm -rf _bin)
