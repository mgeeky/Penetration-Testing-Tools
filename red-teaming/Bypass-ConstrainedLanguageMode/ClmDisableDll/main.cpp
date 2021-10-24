/**
 * This DLL hosts CLR4 environment from within a native binary. This way it is possible to
 * call .NET APIs from an unmanaged runtime.
 *
 * Mariusz Banach, mgeeky, 19'
 *
**/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <metahost.h>
#include <stdio.h>

#pragma comment(lib, "mscoree.lib")

//////////////////////////////////////////////////
//
// Specify below .NET assembly, main class to instantiate and parameters to pass there.

namespace CustomAssemblyParameters {
    LPCWSTR AssemblyName    = L"%TEMP%\\ClmDisableAssembly.dll";
    LPCWSTR TypeName        = L"ClmDisableAssembly.ClmDisableAssembly";
    LPCWSTR MethodName      = L"Start";
    LPCWSTR Argument        = L"(called from native CLR host)";
}

//////////////////////////////////////////////////

#ifdef _DEBUG
#   define msg(x)   MessageBoxW(nullptr, x, L"LoadCLRFromNativeDLL", 0)
#else
#   define msg(x)   ((void)0)
#endif

void DoProcessAttach()
{
    ICLRMetaHost    *metaHost       = nullptr;
    ICLRRuntimeInfo *runtimeInfo    = nullptr;
    ICLRRuntimeHost *runtimeHost    = nullptr;
    IEnumUnknown    *runtime        = nullptr;
    IUnknown        *enumRuntime    = nullptr;

    LPWSTR          frameworkName   = nullptr;
    DWORD           bytes           = 2048;
    DWORD           result          = 0;

    if (CLRCreateInstance(
        CLSID_CLRMetaHost, 
        IID_ICLRMetaHost, 
        reinterpret_cast<LPVOID*>(&metaHost)
    ) != S_OK) {
        msg(L"FAIL: Could not create MetaHost CLR instance.");
        return;
    }

    if (!metaHost || (metaHost->EnumerateInstalledRuntimes(
        &runtime
    ) != S_OK)) {
        msg(L"FAIL: Cannot enumerate installed runtimes.");
        return;
    }

    if (!runtime) {
        msg(L"FAIL: Could not find installed runtimes.");
        return;
    }

    frameworkName = reinterpret_cast<LPWSTR>(LocalAlloc(
        LPTR, 
        bytes
    ));
    if (!frameworkName) {
        msg(L"FAIL: could not allocate 2048 bytes for framework name buffer.");
        return;
    }

    while (runtime->Next(1, &enumRuntime, 0) == S_OK) {
        if (enumRuntime && (enumRuntime->QueryInterface<ICLRRuntimeInfo>(&runtimeInfo) == S_OK)) {
            if (runtimeInfo != nullptr) {
                runtimeInfo->GetVersionString(frameworkName, &bytes);
            }
        }
    }

    if (runtimeInfo == nullptr || (runtimeInfo->GetInterface(
        CLSID_CLRRuntimeHost, 
        IID_ICLRRuntimeHost, 
        reinterpret_cast<LPVOID*>(&runtimeHost)
    ) != S_OK)) {
        msg(L"FAIL: Could not get CLRRuntimeHost interface's reference.");
        return;
    }

    if (runtimeHost == nullptr) {
        msg(L"FAIL: Could not obtain reference to CLRRuntimeHost.");
        return;
    }

    runtimeHost->Start();

    WCHAR assemblyPath[1024] = L"";
    ExpandEnvironmentStringsW(CustomAssemblyParameters::AssemblyName, assemblyPath, _countof(assemblyPath));
    LPCWSTR assemblyPathPtr = assemblyPath;

    HRESULT hres = runtimeHost->ExecuteInDefaultAppDomain(
        assemblyPathPtr,
        CustomAssemblyParameters::TypeName,
        CustomAssemblyParameters::MethodName,
        CustomAssemblyParameters::Argument,
        &result
    );
    if (hres != S_OK) {
        wchar_t msgbuf[1024] = L"";
        swprintf_s(msgbuf, L"FAIL: Could not invoke custom .NET assembly, instantiate it's type or invoke a method. HRESULT = 0x%08x . Assembly path: '%s'", hres, assemblyPath);
        msg(msgbuf);
    }

    //runtimeHost->Stop();
    //runtimeHost->Release();
    runtimeInfo->Release();
    metaHost->Release();
}

BOOLEAN WINAPI DllMain(
    IN HINSTANCE /*hDllHandle*/,
    IN DWORD     nReason,
    IN LPVOID    /*Reserved*/
)
{
    switch (nReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DoProcessAttach();
        break;
    }
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
