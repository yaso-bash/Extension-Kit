CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CC32 = i686-w64-mingw32-gcc
STRIP32 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ./ -w -Wno-incompatible-pointer-types -Os -s -DBOF -c

all: bof

bof:
	@(mkdir -p _bin/Kerbeus-BOF 2>/dev/null) && echo 'creating _bin/Kerbeus-BOF' || echo '_bin/Kerbeus-BOF exists'
	@($(CC64) $(CFLAGS) hash/hash.c -o _bin/Kerbeus-BOF/hash.x64.o    && $(STRIP64) _bin/Kerbeus-BOF/hash.x64.o) && echo '[+] hash' || echo '[!] hash'
	@($(CC32) $(CFLAGS) hash/hash.c -o _bin/Kerbeus-BOF/hash.x32.o    && $(STRIP32) _bin/Kerbeus-BOF/hash.x32.o) && echo '[+] hash x32' || echo '[!] hash x32'
	@($(CC64) $(CFLAGS) klist/klist.c -o _bin/Kerbeus-BOF/klist.x64.o && $(STRIP64) _bin/Kerbeus-BOF/klist.x64.o) && echo '[+] klist' || echo '[!] klist'
	@($(CC32) $(CFLAGS) klist/klist.c -o _bin/Kerbeus-BOF/klist.x32.o && $(STRIP32) _bin/Kerbeus-BOF/klist.x32.o) && echo '[+] klist x32' || echo '[!] klist x32'
	@($(CC64) $(CFLAGS) -DTRIAGE klist/klist.c -o _bin/Kerbeus-BOF/triage.x64.o && $(STRIP64) _bin/Kerbeus-BOF/triage.x64.o) && echo '[+] triage' || echo '[!] triage'
	@($(CC32) $(CFLAGS) -DTRIAGE klist/klist.c -o _bin/Kerbeus-BOF/triage.x32.o && $(STRIP32) _bin/Kerbeus-BOF/triage.x32.o) && echo '[+] triage x32' || echo '[!] triage x32'
	@($(CC64) $(CFLAGS) -DDUMP klist/klist.c -o _bin/Kerbeus-BOF/dump.x64.o     && $(STRIP64) _bin/Kerbeus-BOF/dump.x64.o) && echo '[+] dump' || echo '[!] dump'
	@($(CC32) $(CFLAGS) -DDUMP klist/klist.c -o _bin/Kerbeus-BOF/dump.x32.o     && $(STRIP32) _bin/Kerbeus-BOF/dump.x32.o) && echo '[+] dump x32' || echo '[!] dump x32'
	@($(CC64) $(CFLAGS) describe/describe.c -o _bin/Kerbeus-BOF/describe.x64.o  && $(STRIP64) _bin/Kerbeus-BOF/describe.x64.o) && echo '[+] describe' || echo '[!] describe'
	@($(CC32) $(CFLAGS) describe/describe.c -o _bin/Kerbeus-BOF/describe.x32.o  && $(STRIP32) _bin/Kerbeus-BOF/describe.x32.o) && echo '[+] describe x32' || echo '[!] describe x32'
	@($(CC64) $(CFLAGS) tgtdeleg/tgtdeleg.c -o _bin/Kerbeus-BOF/tgtdeleg.x64.o  && $(STRIP64) _bin/Kerbeus-BOF/tgtdeleg.x64.o) && echo '[+] tgtdeleg' || echo '[!] tgtdeleg'
	@($(CC32) $(CFLAGS) tgtdeleg/tgtdeleg.c -o _bin/Kerbeus-BOF/tgtdeleg.x32.o  && $(STRIP32) _bin/Kerbeus-BOF/tgtdeleg.x32.o) && echo '[+] tgtdeleg x32' || echo '[!] tgtdeleg x32'
	@($(CC64) $(CFLAGS) ptt/ptt.c -o _bin/Kerbeus-BOF/ptt.x64.o                 && $(STRIP64) _bin/Kerbeus-BOF/ptt.x64.o) && echo '[+] ptt' || echo '[!] ptt'
	@($(CC32) $(CFLAGS) ptt/ptt.c -o _bin/Kerbeus-BOF/ptt.x32.o                 && $(STRIP32) _bin/Kerbeus-BOF/ptt.x32.o) && echo '[+] ptt x32' || echo '[!] ptt x32'
	@($(CC64) $(CFLAGS) purge/purge.c -o _bin/Kerbeus-BOF/purge.x64.o           && $(STRIP64) _bin/Kerbeus-BOF/purge.x64.o) && echo '[+] purge' || echo '[!] purge'
	@($(CC32) $(CFLAGS) purge/purge.c -o _bin/Kerbeus-BOF/purge.x32.o           && $(STRIP32) _bin/Kerbeus-BOF/purge.x32.o) && echo '[+] purge x32' || echo '[!] purge x32'
	@($(CC64) $(CFLAGS) asktgt/asktgt.c -o _bin/Kerbeus-BOF/asktgt.x64.o        && $(STRIP64) _bin/Kerbeus-BOF/asktgt.x64.o) && echo '[+] asktgt' || echo '[!] asktgt'
	@($(CC32) $(CFLAGS) asktgt/asktgt.c -o _bin/Kerbeus-BOF/asktgt.x32.o        && $(STRIP32) _bin/Kerbeus-BOF/asktgt.x32.o) && echo '[+] asktgt x32' || echo '[!] asktgt x32'
	@($(CC64) $(CFLAGS) asktgs/asktgs.c -o _bin/Kerbeus-BOF/asktgs.x64.o        && $(STRIP64) _bin/Kerbeus-BOF/asktgs.x64.o) && echo '[+] asktgs' || echo '[!] asktgs'
	@($(CC32) $(CFLAGS) asktgs/asktgs.c -o _bin/Kerbeus-BOF/asktgs.x32.o        && $(STRIP32) _bin/Kerbeus-BOF/asktgs.x32.o) && echo '[+] asktgs x32' || echo '[!] asktgs x32'
	@($(CC64) $(CFLAGS) renew/renew.c -o _bin/Kerbeus-BOF/renew.x64.o           && $(STRIP64) _bin/Kerbeus-BOF/renew.x64.o) && echo '[+] renew' || echo '[!] renew'
	@($(CC32) $(CFLAGS) renew/renew.c -o _bin/Kerbeus-BOF/renew.x32.o           && $(STRIP32) _bin/Kerbeus-BOF/renew.x32.o) && echo '[+] renew x32' || echo '[!] renew x32'
	@($(CC64) $(CFLAGS) changepw/changepw.c -o _bin/Kerbeus-BOF/changepw.x64.o  && $(STRIP64) _bin/Kerbeus-BOF/changepw.x64.o) && echo '[+] changepw' || echo '[!] changepw'
	@($(CC32) $(CFLAGS) changepw/changepw.c -o _bin/Kerbeus-BOF/changepw.x32.o  && $(STRIP32) _bin/Kerbeus-BOF/changepw.x32.o) && echo '[+] changepw x32' || echo '[!] changepw x32'
	@($(CC64) $(CFLAGS) asreproasting/asreproasting.c -o _bin/Kerbeus-BOF/asreproasting.x64.o && $(STRIP64) _bin/Kerbeus-BOF/asreproasting.x64.o) && echo '[+] asreproasting' || echo '[!] asreproasting'
	@($(CC32) $(CFLAGS) asreproasting/asreproasting.c -o _bin/Kerbeus-BOF/asreproasting.x32.o && $(STRIP32) _bin/Kerbeus-BOF/asreproasting.x32.o) && echo '[+] asreproasting x32' || echo '[!] asreproasting x32'
	@($(CC64) $(CFLAGS) kerberoasting/kerberoasting.c -o _bin/Kerbeus-BOF/kerberoasting.x64.o && $(STRIP64) _bin/Kerbeus-BOF/kerberoasting.x64.o) && echo '[+] kerberoasting' || echo '[!] kerberoasting'
	@($(CC32) $(CFLAGS) kerberoasting/kerberoasting.c -o _bin/Kerbeus-BOF/kerberoasting.x32.o && $(STRIP32) _bin/Kerbeus-BOF/kerberoasting.x32.o) && echo '[+] kerberoasting x32' || echo '[!] kerberoasting x32'
	@($(CC64) $(CFLAGS) s4u/s4u.c -o _bin/Kerbeus-BOF/s4u.x64.o             && $(STRIP64) _bin/Kerbeus-BOF/s4u.x64.o) && echo '[+] s4u' || echo '[!] s4u'
	@($(CC32) $(CFLAGS) s4u/s4u.c -o _bin/Kerbeus-BOF/s4u.x32.o             && $(STRIP32) _bin/Kerbeus-BOF/s4u.x32.o) && echo '[+] s4u x32' || echo '[!] s4u x32'
	@($(CC64) $(CFLAGS) s4u/cross_s4u.c -o _bin/Kerbeus-BOF/cross_s4u.x64.o && $(STRIP64) _bin/Kerbeus-BOF/cross_s4u.x64.o) && echo '[+] cross_s4u' || echo '[!] cross_s4u'
	@($(CC32) $(CFLAGS) s4u/cross_s4u.c -o _bin/Kerbeus-BOF/cross_s4u.x32.o && $(STRIP32) _bin/Kerbeus-BOF/cross_s4u.x32.o) && echo '[+] cross_s4u x32' || echo '[!] cross_s4u x32'

clean:
	@(rm -rf _bin)
