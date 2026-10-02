#include "stdafx.h"
#include "BHO.h"

// ---------------------------------------------------------------------------
// DLL instance handle – used by CurlRunner.cpp to locate curl.exe alongside the DLL
// ---------------------------------------------------------------------------
HMODULE g_hModule = NULL;

// ===========================================================================
// ATL module
// ===========================================================================
class CIESSLHelperModule : public CAtlDllModuleT<CIESSLHelperModule>
{
    // Registration is handled manually in DllRegisterServer below;
    // no IDL / type library is needed.
};

CIESSLHelperModule _AtlModule;

// ===========================================================================
// DLL entry point
// ===========================================================================
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        g_hModule = hInstance;
        // We don't need per-thread notifications
        DisableThreadLibraryCalls(hInstance);
    }
    return _AtlModule.DllMain(dwReason, lpReserved);
}

// ===========================================================================
// Standard COM DLL exports (forwarded to the ATL module)
// ===========================================================================
STDAPI DllCanUnloadNow()
{
    return _AtlModule.DllCanUnloadNow();
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    return _AtlModule.DllGetClassObject(rclsid, riid, ppv);
}

// ===========================================================================
// Registry helpers – Win32 only, no CRT string functions
// ===========================================================================
static HRESULT RegWriteSz(HKEY hRoot, LPCWSTR pszKey,
                           LPCWSTR pszName, LPCWSTR pszValue)
{
    HKEY hKey;
    LONG lRet = RegCreateKeyExW(hRoot, pszKey, 0, NULL,
                                 REG_OPTION_NON_VOLATILE, KEY_WRITE,
                                 NULL, &hKey, NULL);
    if (lRet != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(lRet);

    DWORD cbData = (DWORD)((lstrlenW(pszValue) + 1) * sizeof(WCHAR));
    lRet = RegSetValueExW(hKey, pszName, 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(pszValue), cbData);
    RegCloseKey(hKey);
    return HRESULT_FROM_WIN32(lRet);
}

static HRESULT RegWriteDword(HKEY hRoot, LPCWSTR pszKey,
                              LPCWSTR pszName, DWORD dwValue)
{
    HKEY hKey;
    LONG lRet = RegCreateKeyExW(hRoot, pszKey, 0, NULL,
                                 REG_OPTION_NON_VOLATILE, KEY_WRITE,
                                 NULL, &hKey, NULL);
    if (lRet != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(lRet);

    lRet = RegSetValueExW(hKey, pszName, 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&dwValue), sizeof(DWORD));
    RegCloseKey(hKey);
    return HRESULT_FROM_WIN32(lRet);
}

// "{6AF3E10B-...}" for CLSID_IESSLHelper.
static void GetClsidString(WCHAR (&sz)[40])
{
    StringFromGUID2(CLSID_IESSLHelper, sz, _countof(sz));
}

// ===========================================================================
// DllRegisterServer
//
// Writes five registry entries:
//   HKCR\CLSID\{...}                                              = "IESSLHelper"
//   HKCR\CLSID\{...}\InprocServer32                              = <dll path>
//   HKCR\CLSID\{...}\InprocServer32\ThreadingModel               = "Apartment"
//   HKLM\...\Browser Helper Objects\{...}                        = "IESSLHelper"
//   HKLM\...\Browser Helper Objects\{...}\NoExplorer             = 1
// ===========================================================================
STDAPI DllRegisterServer()
{
    WCHAR szDllPath[MAX_PATH];
    GetModuleFileNameW(g_hModule, szDllPath, MAX_PATH);

    WCHAR szClsid[40];
    GetClsidString(szClsid);

    WCHAR szKey[256];
    HRESULT hr;

    // HKCR\CLSID\{...}
    wsprintfW(szKey, L"CLSID\\%s", szClsid);
    hr = RegWriteSz(HKEY_CLASSES_ROOT, szKey, NULL, L"IESSLHelper");
    if (FAILED(hr)) return hr;

    // HKCR\CLSID\{...}\InprocServer32
    wsprintfW(szKey, L"CLSID\\%s\\InprocServer32", szClsid);
    hr = RegWriteSz(HKEY_CLASSES_ROOT, szKey, NULL, szDllPath);
    if (FAILED(hr)) return hr;

    hr = RegWriteSz(HKEY_CLASSES_ROOT, szKey, L"ThreadingModel", L"Apartment");
    if (FAILED(hr)) return hr;

    // HKLM\...\Browser Helper Objects\{...}
    wsprintfW(szKey,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
        L"Explorer\\Browser Helper Objects\\%s",
        szClsid);
    hr = RegWriteSz(HKEY_LOCAL_MACHINE, szKey, NULL, L"IESSLHelper");
    if (FAILED(hr)) return hr;

    // NoExplorer = 1 prevents the BHO from loading in Windows Explorer
    hr = RegWriteDword(HKEY_LOCAL_MACHINE, szKey, L"NoExplorer", 1);
    return hr;
}

// ===========================================================================
// DllUnregisterServer
// ===========================================================================
STDAPI DllUnregisterServer()
{
    WCHAR szClsid[40];
    GetClsidString(szClsid);

    WCHAR szKey[256];

    wsprintfW(szKey, L"CLSID\\%s", szClsid);
    SHDeleteKeyW(HKEY_CLASSES_ROOT, szKey);

    wsprintfW(szKey,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
        L"Explorer\\Browser Helper Objects\\%s",
        szClsid);
    SHDeleteKeyW(HKEY_LOCAL_MACHINE, szKey);

    return S_OK;
}
