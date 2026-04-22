#pragma once

#define WINVER       0x0501
#define _WIN32_WINNT 0x0501

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <objbase.h>
#include <atlbase.h>    // CComPtr, CComCoClass, CAtlDllModuleT ...
#include <atlcom.h>     // IObjectWithSiteImpl ...
#include <urlmon.h>     // IInternetProtocol, IInternetSession, FindMimeFromData
#include <shlobj.h>     // SHGetFolderPathW, CSIDL_DESKTOPDIRECTORY
#include <shlwapi.h>    // PathRemoveFileSpecW, PathAppendW,
                        // PathFileExistsW, SHDeleteKeyW
