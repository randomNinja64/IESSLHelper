#include "stdafx.h"
#include "CurlRunner.h"
#include <winhttp.h>
#include "Util.h"

extern HMODULE g_hModule; // defined in dllmain.cpp

namespace curlbho {

// Returns true iff every character in psz is an ASCII letter (safe for -X).
static bool VerbIsAlpha(LPCWSTR psz)
{
    if (!psz || !*psz) return false;
    for (; *psz; ++psz)
        if (!((*psz >= L'A' && *psz <= L'Z') || (*psz >= L'a' && *psz <= L'z')))
            return false;
    return true;
}

// Block until curl opens hPipe (or exits), write data, then close the pipe
// so the reader sees EOF.  The pipe lives only in memory.
static void ServePipe(HANDLE hPipe, HANDLE hProcess, const void* data, DWORD cb)
{
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hEvent)
    {
        OVERLAPPED ov;
        ZeroMemory(&ov, sizeof(ov));
        ov.hEvent = hEvent;

        BOOL bConnected = ConnectNamedPipe(hPipe, &ov);
        DWORD dwPipeErr = GetLastError();

        if (!bConnected)
        {
            if (dwPipeErr == ERROR_PIPE_CONNECTED)
            {
                bConnected = TRUE;
            }
            else if (dwPipeErr == ERROR_IO_PENDING)
            {
                HANDLE waitOn[2] = { hEvent, hProcess };
                DWORD dw = WaitForMultipleObjects(2, waitOn, FALSE, INFINITE);
                if (dw == WAIT_OBJECT_0)
                {
                    DWORD transferred = 0;
                    bConnected = GetOverlappedResult(hPipe, &ov, &transferred, FALSE);
                }
                else
                {
                    CancelIo(hPipe);
                }
            }
        }

        CloseHandle(hEvent);

        if (bConnected && data && cb)
        {
            DWORD cbWritten = 0;
            WriteFile(hPipe, data, cb, &cbWritten, NULL);
        }
    }
    CloseHandle(hPipe);
}

// CreateProcess accepts at most 32767 characters, including the terminator.
static const int kCmdMax = 32767;

// Appends fmt (one %s) to szCmd. False when the result would not fit.
static bool AppendArg(WCHAR* szCmd, int* pcch, LPCWSTR fmt, LPCWSTR arg)
{
    int need = lstrlenW(arg) + lstrlenW(fmt) - 2;
    if (need < 0 || *pcch > kCmdMax - 1 - need)
        return false;
    *pcch += wsprintfW(szCmd + *pcch, fmt, arg);
    return true;
}

// Appends one -H argument. Quotes in the value become spaces.
static bool AppendHeader(WCHAR* szCmd, int* pcch, LPCWSTR name, LPCWSTR value)
{
    int nlen = lstrlenW(name);
    int vlen = value ? lstrlenW(value) : 0;
    int need = nlen + vlen + 8; //  -H "name: value"
    if (*pcch > kCmdMax - 1 - need)
        return false;
    WCHAR* p = szCmd + *pcch;
    for (LPCWSTR s = L" -H \""; *s; ) *p++ = *s++;
    for (LPCWSTR s = name; *s; ) *p++ = *s++;
    *p++ = L':';
    *p++ = L' ';
    for (int i = 0; i < vlen; ++i)
    {
        WCHAR c = value[i];
        if (c == L'"' || c == L'\r' || c == L'\n') c = L' ';
        *p++ = c;
    }
    *p++ = L'"';
    *p = 0;
    *pcch = (int)(p - szCmd);
    return true;
}

// Quoted URL. " is written as %22 so it cannot close the argument. An odd
// run of trailing backslashes is padded so it cannot escape that quote.
static bool AppendUrl(WCHAR* szCmd, int* pcch, LPCWSTR url)
{
    if (!url) url = L"";
    int n = lstrlenW(url);
    if (n < 0 || n > kCmdMax / 3)
        return false;
    int need = 4 + n * 3; // space, quotes, and every char turning into %22
    if (*pcch > kCmdMax - 1 - need)
        return false;
    WCHAR* p = szCmd + *pcch;
    *p++ = L' ';
    *p++ = L'"';
    WCHAR* start = p;
    for (int i = 0; i < n; ++i)
    {
        WCHAR c = url[i];
        if (c == L'"') { *p++ = L'%'; *p++ = L'2'; *p++ = L'2'; }
        else if (c != L'\r' && c != L'\n') *p++ = c;
    }
    int slashes = 0;
    for (WCHAR* q = p; q > start && q[-1] == L'\\'; --q) ++slashes;
    if (slashes % 2) *p++ = L'\\';
    *p++ = L'"';
    *p = 0;
    *pcch = (int)(p - szCmd);
    return true;
}

// Appends one already-formed header line as -H. A quote becomes an apostrophe.
static bool AppendHeaderLine(WCHAR* szCmd, int* pcch, LPCWSTR line, int len)
{
    int need = len + 6; //  -H "line"
    if (len < 0 || *pcch > kCmdMax - 1 - need)
        return false;
    WCHAR* p = szCmd + *pcch;
    for (LPCWSTR s = L" -H \""; *s; ) *p++ = *s++;
    for (int i = 0; i < len; ++i)
    {
        WCHAR c = line[i];
        if (c == L'"') c = L'\'';
        *p++ = c;
    }
    *p++ = L'"';
    *p = 0;
    *pcch = (int)(p - szCmd);
    return true;
}

static bool AppendLit(WCHAR* szCmd, int* pcch, LPCWSTR text)
{
    int n = lstrlenW(text);
    if (*pcch > kCmdMax - 1 - n)
        return false;
    lstrcpyW(szCmd + *pcch, text);
    *pcch += n;
    return true;
}

// Copies one IE proxy token (up to ';' ) and drops quotes and line breaks.
static void CopyProxyToken(const WCHAR* src, WCHAR* dst, int cch)
{
    int n = 0;
    while (src && *src && *src != L';' && n < cch - 1)
    {
        if (*src != L'"' && *src != L'\r' && *src != L'\n')
            dst[n++] = *src;
        ++src;
    }
    while (n > 0 && (dst[n - 1] == L' ' || dst[n - 1] == L'\t'))
        --n;
    dst[n] = 0;
}

// "https=host:port;http=host:port", or a bare "host:port". HTTPS uses the
// https= entry, then http=, then a bare host. curl wants a scheme.
static void CurlProxyUrl(LPCWSTR src, WCHAR* dst, int cch)
{
    dst[0] = 0;
    if (!src || !src[0] || cch < 8)
        return;
    const WCHAR* tok = NULL;
    for (const WCHAR* p = src; *p; )
    {
        if (_wcsnicmp(p, L"https=", 6) == 0) { tok = p + 6; break; }
        if (!tok && _wcsnicmp(p, L"http=", 5) == 0) tok = p + 5;
        while (*p && *p != L';') ++p;
        if (*p == L';') ++p;
    }
    WCHAR host[256];
    if (tok)
        CopyProxyToken(tok, host, _countof(host));
    else if (!wcschr(src, L'='))
        CopyProxyToken(src, host, _countof(host));
    else
        host[0] = 0;
    if (!host[0])
        return;
    bool hasScheme = wcsstr(host, L"://") != NULL;
    if (!hasScheme)
    {
        lstrcpynW(dst, L"http://", cch);
        lstrcpynW(dst + 7, host, cch - 7);
    }
    else
        lstrcpynW(dst, host, cch);
    // user:pass@ stays off the command line. A 407 uses the config pipe.
    WCHAR* scheme = wcsstr(dst, L"://");
    WCHAR* at = scheme ? wcschr(scheme + 3, L'@') : NULL;
    if (at)
    {
        int keep = (int)(scheme + 3 - dst);
        memmove(dst + keep, at + 1, (lstrlenW(at + 1) + 1) * sizeof(WCHAR));
    }
}

// IE separates the bypass list with semicolons. curl wants commas.
static void BypassToNoProxy(LPCWSTR src, WCHAR* dst, int cch)
{
    int n = 0;
    for (; src && *src && n < cch - 1; ++src)
    {
        if (*src == L';')
            dst[n++] = L',';
        else if (*src != L' ' && *src != L'\t' && *src != L'"' &&
                 *src != L'\r' && *src != L'\n')
            dst[n++] = *src;
    }
    dst[n] = 0;
}

static void FreeProxyStr(LPWSTR p)
{
    if (p) GlobalFree(p);
}

// Fills szProxy ("http://host:port") and szNoProxy from IE's settings for
// this URL. Both are empty when IE would connect directly.
static void LookupIeProxy(LPCWSTR pszURL, WCHAR* szProxy, int cchProxy,
                          WCHAR* szNoProxy, int cchNoProxy)
{
    szProxy[0] = szNoProxy[0] = 0;
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    if (!WinHttpGetIEProxyConfigForCurrentUser(&cfg))
        return;

    WINHTTP_PROXY_INFO info;
    ZeroMemory(&info, sizeof(info));
    BOOL resolved = FALSE;
    if (cfg.fAutoDetect || (cfg.lpszAutoConfigUrl && cfg.lpszAutoConfigUrl[0]))
    {
        HINTERNET hSession = WinHttpOpen(L"IESSLHelper",
            WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession)
        {
            WINHTTP_AUTOPROXY_OPTIONS opt;
            ZeroMemory(&opt, sizeof(opt));
            if (cfg.fAutoDetect)
            {
                opt.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
                opt.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP |
                                        WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            }
            if (cfg.lpszAutoConfigUrl && cfg.lpszAutoConfigUrl[0])
            {
                opt.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
                opt.lpszAutoConfigUrl = cfg.lpszAutoConfigUrl;
            }
            opt.fAutoLogonIfChallenged = TRUE;
            resolved = WinHttpGetProxyForUrl(hSession, pszURL, &opt, &info);
            WinHttpCloseHandle(hSession);
        }
    }

    LPCWSTR proxy = NULL;
    LPCWSTR bypass = NULL;
    if (resolved && info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY)
    {
        proxy = info.lpszProxy;
        bypass = info.lpszProxyBypass;
    }
    else if (!resolved && cfg.lpszProxy && cfg.lpszProxy[0])
    {
        proxy = cfg.lpszProxy;
        bypass = cfg.lpszProxyBypass;
    }
    if (proxy)
        CurlProxyUrl(proxy, szProxy, cchProxy);
    if (szProxy[0] && bypass)
        BypassToNoProxy(bypass, szNoProxy, cchNoProxy);

    FreeProxyStr(info.lpszProxy);
    FreeProxyStr(info.lpszProxyBypass);
    FreeProxyStr(cfg.lpszAutoConfigUrl);
    FreeProxyStr(cfg.lpszProxy);
    FreeProxyStr(cfg.lpszProxyBypass);
}

// curl config for --anyauth / --proxy-anyauth. Quotes and backslashes are
// escaped, and line breaks are dropped so a password cannot add a line.
static char* BuildAuthConfig(LPCWSTR user, LPCWSTR proxyUser, DWORD* pcb)
{
    *pcb = 0;
    int cap = 64;
    if (user) cap += lstrlenW(user) * 4 + 16;
    if (proxyUser) cap += lstrlenW(proxyUser) * 4 + 32;
    char* dst = (char*)LocalAlloc(LMEM_FIXED, cap);
    if (!dst)
        return NULL;
    int at = 0;
    const LPCWSTR vals[2] = { user, proxyUser };
    const char* keys[2] = { "user = \"", "proxy-user = \"" };
    for (int k = 0; k < 2; ++k)
    {
        if (!vals[k])
            continue;
        int klen = lstrlenA(keys[k]);
        if (at + klen >= cap) break;
        memcpy(dst + at, keys[k], klen);
        at += klen;
        int wlen = lstrlenW(vals[k]);
        int n = WideCharToMultiByte(CP_ACP, 0, vals[k], wlen, NULL, 0, NULL, NULL);
        char* tmp = n > 0 ? (char*)LocalAlloc(LMEM_FIXED, n) : NULL;
        if (tmp)
            WideCharToMultiByte(CP_ACP, 0, vals[k], wlen, tmp, n, NULL, NULL);
        for (int i = 0; tmp && i < n && at + 2 < cap; ++i)
        {
            char c = tmp[i];
            if (c == '\r' || c == '\n')
                continue;
            if (c == '"' || c == '\\')
                dst[at++] = '\\';
            dst[at++] = c;
        }
        if (tmp) LocalFree(tmp);
        if (at + 2 < cap)
        {
            dst[at++] = '"';
            dst[at++] = '\n';
        }
    }
    dst[at] = 0;
    *pcb = (DWORD)at;
    return dst;
}

bool StartCurl(const CurlRequest& req, CurlProcess* proc)
{
    proc->hProcess = NULL;
    proc->hOut     = INVALID_HANDLE_VALUE;
    proc->hErr     = INVALID_HANDLE_VALUE;

    WCHAR szCurl[MAX_PATH];
    GetModuleFileNameW(g_hModule, szCurl, MAX_PATH);
    PathRemoveFileSpecW(szCurl);
    PathAppendW(szCurl, L"curl.exe");
    if (!PathFileExistsW(szCurl))
        lstrcpyW(szCurl, L"curl.exe");

    // -----------------------------------------------------------------------
    //  Named pipe for the request body (POST / PUT / etc.)
    //  The server end (us) is OUTBOUND: we write, curl reads.
    // -----------------------------------------------------------------------
    WCHAR  szPipeName[96] = L"";
    HANDLE hPipe          = INVALID_HANDLE_VALUE;
    WCHAR  szCookiePipe[96] = L"";
    HANDLE hCookiePipe      = INVALID_HANDLE_VALUE;
    WCHAR  szConfigPipe[96] = L"";
    HANDLE hConfigPipe      = INVALID_HANDLE_VALUE;
    DWORD  cbConfig         = 0;
    char*  pConfig          = NULL;

    static LONG s_seq = 0;
    const bool bHasBody = (req.pPostData != NULL && req.cbPostData > 0);
    const bool bHasCookies = (req.pCookieJar != NULL && req.cbCookieJar > 0);
    const bool bHasConfig = (req.pszUser && req.pszUser[0]) ||
                            (req.pszProxyUser && req.pszProxyUser[0]);

    if (bHasConfig)
    {
        pConfig = BuildAuthConfig(req.pszUser, req.pszProxyUser, &cbConfig);
        if (!pConfig || cbConfig == 0)
        {
            if (pConfig) LocalFree(pConfig);
            return false;
        }
        LONG seq = InterlockedIncrement(&s_seq);
        wsprintfW(szConfigPipe,
            L"\\\\.\\pipe\\curlbho_au_%08X_%08X",
            GetCurrentProcessId(), (DWORD)seq);
        hConfigPipe = CreateNamedPipeW(
            szConfigPipe,
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 0, cbConfig + 1, 0, NULL);
        if (hConfigPipe == INVALID_HANDLE_VALUE)
        {
            LocalFree(pConfig);
            return false;
        }
    }

    if (bHasCookies)
    {
        LONG seq = InterlockedIncrement(&s_seq);
        wsprintfW(szCookiePipe,
            L"\\\\.\\pipe\\curlbho_ck_%08X_%08X",
            GetCurrentProcessId(), (DWORD)seq);

        hCookiePipe = CreateNamedPipeW(
            szCookiePipe,
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 0, req.cbCookieJar + 1, 0, NULL);

        if (hCookiePipe == INVALID_HANDLE_VALUE)
        {
            if (hConfigPipe != INVALID_HANDLE_VALUE) CloseHandle(hConfigPipe);
            if (pConfig) LocalFree(pConfig);
            return false;
        }
    }

    if (bHasBody)
    {
        LONG seq = InterlockedIncrement(&s_seq);
        wsprintfW(szPipeName,
            L"\\\\.\\pipe\\curlbho_%08X_%08X",
            GetCurrentProcessId(), (DWORD)seq);

        hPipe = CreateNamedPipeW(
            szPipeName,
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,                  // max instances
            0,                  // outbound buffer hint (server writes)
            req.cbPostData + 1, // inbound buffer hint  (client reads)
            0,                  // default timeout
            NULL);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            if (hConfigPipe != INVALID_HANDLE_VALUE) CloseHandle(hConfigPipe);
            if (hCookiePipe != INVALID_HANDLE_VALUE) CloseHandle(hCookiePipe);
            if (pConfig) LocalFree(pConfig);
            return false;
        }
    }

    // -----------------------------------------------------------------------
    //  Build command line.  32767 is the CreateProcess limit. Any piece
    //  that does not fit fails the launch; nothing is written past the end.
    // -----------------------------------------------------------------------
    WCHAR* szCmd = (WCHAR*)LocalAlloc(LMEM_FIXED, kCmdMax * sizeof(WCHAR));
    if (!szCmd)
    {
        if (hConfigPipe != INVALID_HANDLE_VALUE) CloseHandle(hConfigPipe);
        if (hCookiePipe != INVALID_HANDLE_VALUE) CloseHandle(hCookiePipe);
        if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
        if (pConfig) LocalFree(pConfig);
        return false;
    }
    int cch = 0;
    szCmd[0] = 0;
    // --compressed: ask for and transparently decode gzip/deflate/brotli.
    // URLMon forwards IE's "Accept-Encoding: gzip, deflate" via
    // BINDSTRING_HEADERS, so without this curl writes the raw
    // compressed bytes to the output file, MIME sniffing fails (the body
    // looks like application/x-gzip), and IE shows the download dialog
    // instead of rendering the page.
    // --connect-timeout bounds how long we'll wait for an unreachable
    // host; there's no overall --max-time so big downloads can take as
    // long as they need.
    // -i: response headers come first on stdout, so the caller can act on
    // them before the body has finished arriving.
    bool bCmd = AppendArg(szCmd, &cch,
        L"\"%s\" -i --ssl-no-revoke --compressed -sS --connect-timeout 30",
        szCurl);

    WCHAR szProxy[512];
    WCHAR szNoProxy[2048];
    LookupIeProxy(req.pszURL, szProxy, _countof(szProxy),
                  szNoProxy, _countof(szNoProxy));
    if (bCmd && szProxy[0])
        bCmd = AppendArg(szCmd, &cch, L" --proxy \"%s\"", szProxy);
    if (bCmd && szNoProxy[0])
        bCmd = AppendArg(szCmd, &cch, L" --noproxy \"%s\"", szNoProxy);
    if (bCmd && req.pszUser && req.pszUser[0])
        bCmd = AppendLit(szCmd, &cch, L" --anyauth");
    if (bCmd && req.pszProxyUser && req.pszProxyUser[0])
        bCmd = AppendLit(szCmd, &cch, L" --proxy-anyauth");
    if (bCmd && szConfigPipe[0])
        bCmd = AppendArg(szCmd, &cch, L" --config \"%s\"", szConfigPipe);

    // No '=' in the pipe path, so curl opens it as a cookie file. The
    // bytes stay in the pipe's memory buffer; curl reads them at startup.
    if (bCmd && bHasCookies)
        bCmd = AppendArg(szCmd, &cch, L" -b \"%s\"", szCookiePipe);

    // Verb (-X POST / -X PUT / etc.)
    const bool bCustomVerb = VerbIsAlpha(req.pszVerb) &&
                             _wcsicmp(req.pszVerb, L"GET") != 0;
    if (bCmd && bCustomVerb)
        bCmd = AppendArg(szCmd, &cch, L" -X %s", req.pszVerb);

    if (bCmd && req.pszContentType && req.pszContentType[0])
        bCmd = AppendHeader(szCmd, &cch, L"Content-Type", req.pszContentType);

    // Extra request headers (CRLF-delimited string from URLMon).
    // Cookie is supplied from WinInet on the cookie pipe.
    if (bCmd && req.pszExtraHeaders && req.pszExtraHeaders[0])
    {
        LPCWSTR pLine = req.pszExtraHeaders;
        while (bCmd && *pLine)
        {
            LPCWSTR pEnd = pLine;
            while (*pEnd && *pEnd != L'\r' && *pEnd != L'\n') ++pEnd;
            int len = (int)(pEnd - pLine);
            const bool bCookie = len >= 7 && _wcsnicmp(pLine, L"Cookie:", 7) == 0;
            if (len > 0 && !bCookie)
                bCmd = AppendHeaderLine(szCmd, &cch, pLine, len);
            pLine = pEnd;
            while (*pLine == L'\r' || *pLine == L'\n') ++pLine;
        }
    }

    // Request body via named pipe (@path tells curl to read from the path)
    if (bCmd && bHasBody)
        bCmd = AppendArg(szCmd, &cch, L" --data-binary \"@%s\"", szPipeName);

    // URL. Quotes are percent-encoded so they stay inside this one argument.
    if (bCmd)
        bCmd = AppendUrl(szCmd, &cch, req.pszURL);

    if (!bCmd)
    {
        LocalFree(szCmd);
        if (hConfigPipe != INVALID_HANDLE_VALUE) CloseHandle(hConfigPipe);
        if (hCookiePipe != INVALID_HANDLE_VALUE) CloseHandle(hCookiePipe);
        if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
        if (pConfig) LocalFree(pConfig);
        return false;
    }

    // -----------------------------------------------------------------------
    //  Launch curl
    // -----------------------------------------------------------------------
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    ScopedHandle hNul(CreateFileW(L"NUL",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &sa, OPEN_EXISTING, 0, NULL));

    // Anonymous pipe for stdout.  Write end is inheritable (curl writes to it);
    // read end is non-inheritable (only we drain it after launching curl).
    HANDLE hOutReadRaw = INVALID_HANDLE_VALUE, hOutWriteRaw = INVALID_HANDLE_VALUE;
    CreatePipe(&hOutReadRaw, &hOutWriteRaw, &sa, 0);
    ScopedHandle hOutRead(hOutReadRaw);
    ScopedHandle hOutWrite(hOutWriteRaw);
    if (hOutRead.Valid())
        SetHandleInformation(hOutRead.Get(), HANDLE_FLAG_INHERIT, 0);

    // Anonymous pipe for stderr.  Write end is inheritable (curl writes to it);
    // read end is non-inheritable.  The caller drains it while reading stdout.
    HANDLE hErrReadRaw = INVALID_HANDLE_VALUE, hErrWriteRaw = INVALID_HANDLE_VALUE;
    CreatePipe(&hErrReadRaw, &hErrWriteRaw, &sa, 0);
    ScopedHandle hErrRead(hErrReadRaw);
    ScopedHandle hErrWrite(hErrWriteRaw);
    if (hErrRead.Valid())
        SetHandleInformation(hErrRead.Get(), HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    // Without redirected stdio there is no response to read.
    BOOL bOk = hNul.Valid() && hOutRead.Valid() && hOutWrite.Valid() &&
               hErrRead.Valid() && hErrWrite.Valid();
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    if (bOk)
    {
        si.dwFlags   |= STARTF_USESTDHANDLES;
        si.hStdInput  = hNul.Get();
        si.hStdOutput = hOutWrite.Get();
        si.hStdError  = hErrWrite.Get();
        bOk = CreateProcessW(NULL, szCmd, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }
    LocalFree(szCmd);
    hNul.Close();
    hOutWrite.Close(); // close our write ends so pipes signal EOF when curl exits
    hErrWrite.Close();

    if (!bOk)
    {
        if (hConfigPipe != INVALID_HANDLE_VALUE) CloseHandle(hConfigPipe);
        if (hCookiePipe != INVALID_HANDLE_VALUE) CloseHandle(hCookiePipe);
        if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
        if (pConfig) LocalFree(pConfig);
        return false;
    }
    CloseHandle(pi.hThread);

    // Config first: curl reads it at startup, before the cookie jar.
    if (hConfigPipe != INVALID_HANDLE_VALUE)
        ServePipe(hConfigPipe, pi.hProcess, pConfig, cbConfig);
    if (pConfig) LocalFree(pConfig);

    // Cookie file next: curl reads it at startup, before the request body.
    if (bHasCookies && hCookiePipe != INVALID_HANDLE_VALUE)
        ServePipe(hCookiePipe, pi.hProcess, req.pCookieJar, req.cbCookieJar);

    // POST body. Overlapped connect also wakes if curl exits first.
    if (bHasBody && hPipe != INVALID_HANDLE_VALUE)
        ServePipe(hPipe, pi.hProcess, req.pPostData, req.cbPostData);

    proc->hProcess = pi.hProcess;
    proc->hOut     = hOutRead.Detach();
    proc->hErr     = hErrRead.Detach();
    return true;
}

DWORD FinishCurl(CurlProcess* proc)
{
    DWORD dwExit = FETCH_LAUNCH_FAILED;
    if (proc->hOut != INVALID_HANDLE_VALUE)
    {
        CloseHandle(proc->hOut);
        proc->hOut = INVALID_HANDLE_VALUE;
    }
    if (proc->hErr != INVALID_HANDLE_VALUE)
    {
        CloseHandle(proc->hErr);
        proc->hErr = INVALID_HANDLE_VALUE;
    }
    if (proc->hProcess)
    {
        WaitForSingleObject(proc->hProcess, INFINITE);
        GetExitCodeProcess(proc->hProcess, &dwExit);
        CloseHandle(proc->hProcess);
        proc->hProcess = NULL;
    }
    return dwExit;
}

} // namespace curlbho
