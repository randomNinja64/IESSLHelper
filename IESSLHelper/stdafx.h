#pragma once

#define WINVER       0x0501
#define _WIN32_WINNT 0x0501
#define _WIN32_IE    0x0600   // IE 6.0 API surface (IWebBrowser2, etc.)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <objbase.h>
#include <atlbase.h>    // CComPtr, CComCoClass, CAtlDllModuleT ...
#include <atlcom.h>     // IObjectWithSiteImpl, IDispEventSimpleImpl ...
#include <exdisp.h>     // IWebBrowser2, DWebBrowserEvents2
#include <exdispid.h>   // DISPID_BEFORENAVIGATE2, DISPID_DOCUMENTCOMPLETE
#include <mshtml.h>     // IHTMLDocument2 (document.write injection)
#include <urlmon.h>     // IInternetProtocol, IInternetSession, FindMimeFromData
#include <shlwapi.h>    // StrCmpNIW, PathRemoveFileSpecW, PathAppendW,
                        // PathFileExistsW, UrlCreateFromPathW, SHDeleteKeyW
