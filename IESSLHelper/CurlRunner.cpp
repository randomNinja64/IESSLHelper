#include "stdafx.h"
#include "CurlRunner.h"
#include "Util.h"
#include <sddl.h>

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

typedef BOOL (WINAPI* PFN_GetNamedPipeClientProcessId)(HANDLE, PULONG);

// False when the connected client is known to be a process other than
// dwPid.  GetNamedPipeClientProcessId is Vista+, so XP skips the check.
static bool PipeClientIs(HANDLE hPipe, DWORD dwPid)
{
    PFN_GetNamedPipeClientProcessId pfn = (PFN_GetNamedPipeClientProcessId)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetNamedPipeClientProcessId");
    if (!pfn)
        return true;
    ULONG pid = 0;
    return pfn(hPipe, &pid) && pid == dwPid;
}

// Security descriptor that lets only SYSTEM and this process's user open
// an object.  Free with LocalFree.  NULL on failure.
static PSECURITY_DESCRIPTOR CreateUserOnlySD()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return NULL;
    DWORD_PTR tokenUser[32]; // TOKEN_USER plus a SID of at most 68 bytes
    DWORD cb = 0;
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (GetTokenInformation(hToken, TokenUser, tokenUser, sizeof(tokenUser), &cb))
    {
        LPWSTR pszSid = NULL;
        if (ConvertSidToStringSidW(((TOKEN_USER*)tokenUser)->User.Sid, &pszSid))
        {
            WCHAR szSddl[320];
            wsprintfW(szSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;%s)", pszSid);
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    szSddl, SDDL_REVISION_1, &pSD, NULL))
                pSD = NULL;
            LocalFree(pszSid);
        }
    }
    CloseHandle(hToken);
    return pSD;
}

// Creates an outbound, single-instance pipe only the current user and
// SYSTEM can open, under a random name written to szName.
// INVALID_HANDLE_VALUE on failure.
static HANDLE CreatePrivatePipe(LPCWSTR prefix, DWORD cbHint,
                                WCHAR* szName, int cchName)
{
    GUID  guid;
    WCHAR szGuid[40];
    if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(guid, szGuid, _countof(szGuid)))
        return INVALID_HANDLE_VALUE;
    if (lstrlenW(prefix) + lstrlenW(szGuid) + 24 >= cchName)
        return INVALID_HANDLE_VALUE;
    wsprintfW(szName, L"\\\\.\\pipe\\iesslhelper_%s_%s", prefix, szGuid);

    PSECURITY_DESCRIPTOR pSD = CreateUserOnlySD();
    if (!pSD)
        return INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), pSD, FALSE };

    const DWORD dwOpen = PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED;
    const DWORD dwMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;
    HANDLE h = CreateNamedPipeW(szName, dwOpen | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                dwMode, 1, 0, cbHint, 0, &sa);
    // FILE_FLAG_FIRST_PIPE_INSTANCE needs XP SP2.
    if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER)
        h = CreateNamedPipeW(szName, dwOpen, dwMode, 1, 0, cbHint, 0, &sa);
    LocalFree(pSD);
    return h;
}

// Writes all of data to an overlapped pipe.  Gives up if curl exits.
static void WritePipe(HANDLE hPipe, HANDLE hProcess, HANDLE hEvent,
                      const BYTE* data, DWORD cb)
{
    while (cb)
    {
        OVERLAPPED ov;
        ZeroMemory(&ov, sizeof(ov));
        ov.hEvent = hEvent;
        DWORD n = 0;
        if (!WriteFile(hPipe, data, cb, NULL, &ov))
        {
            if (GetLastError() != ERROR_IO_PENDING)
                return;
            HANDLE waitOn[2] = { hEvent, hProcess };
            if (WaitForMultipleObjects(2, waitOn, FALSE, INFINITE) != WAIT_OBJECT_0)
            {
                CancelIo(hPipe);
                GetOverlappedResult(hPipe, &ov, &n, TRUE);
                return;
            }
        }
        if (!GetOverlappedResult(hPipe, &ov, &n, FALSE) || n == 0)
            return;
        data += n;
        cb   -= n;
    }
}

// One outbound pipe and the bytes curl should read from it.
struct PipeJob
{
    HANDLE      hPipe;
    const BYTE* data;
    DWORD       cb;
};

static const int kMaxPipes = 2;

// Serves every pipe in whatever order curl opens them: curl reads
// --data-binary while parsing arguments but the cookie file only when the
// transfer starts.  Each pipe is closed once written so curl sees EOF.
// Returns when all are served or curl has exited.  Nothing is written
// unless the client is curl (dwPid).  Closes every hPipe.
static void ServePipes(PipeJob* jobs, int nJobs, HANDLE hProcess, DWORD dwPid)
{
    enum { kDone, kWaiting, kConnected };
    OVERLAPPED ov[kMaxPipes];
    HANDLE     ev[kMaxPipes];
    int        state[kMaxPipes];
    for (int i = 0; i < nJobs; ++i)
    {
        ZeroMemory(&ov[i], sizeof(ov[i]));
        ev[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        ov[i].hEvent = ev[i];
        state[i] = kDone;
        if (!ev[i])
            continue;
        if (ConnectNamedPipe(jobs[i].hPipe, &ov[i]) || GetLastError() == ERROR_PIPE_CONNECTED)
            state[i] = kConnected;
        else if (GetLastError() == ERROR_IO_PENDING)
            state[i] = kWaiting;
    }

    for (;;)
    {
        for (int i = 0; i < nJobs; ++i)
        {
            if (state[i] != kConnected)
                continue;
            if (jobs[i].data && jobs[i].cb && PipeClientIs(jobs[i].hPipe, dwPid))
                WritePipe(jobs[i].hPipe, hProcess, ev[i], jobs[i].data, jobs[i].cb);
            CloseHandle(jobs[i].hPipe);
            jobs[i].hPipe = INVALID_HANDLE_VALUE;
            state[i] = kDone;
        }

        HANDLE waitOn[kMaxPipes + 1];
        int    which[kMaxPipes];
        int    k = 0;
        for (int i = 0; i < nJobs; ++i)
            if (state[i] == kWaiting) { waitOn[k] = ev[i]; which[k++] = i; }
        if (!k)
            break;
        waitOn[k] = hProcess;
        const DWORD dw = WaitForMultipleObjects(k + 1, waitOn, FALSE, INFINITE);
        if (dw >= WAIT_OBJECT_0 + k)
            break;   // curl exited, or the wait failed
        const int i = which[dw - WAIT_OBJECT_0];
        DWORD t = 0;
        state[i] = GetOverlappedResult(jobs[i].hPipe, &ov[i], &t, FALSE) ? kConnected : kDone;
    }

    for (int i = 0; i < nJobs; ++i)
    {
        if (state[i] == kWaiting)
        {
            DWORD t = 0;
            CancelIo(jobs[i].hPipe);
            GetOverlappedResult(jobs[i].hPipe, &ov[i], &t, TRUE);
        }
        if (jobs[i].hPipe != INVALID_HANDLE_VALUE)
            CloseHandle(jobs[i].hPipe);
        if (ev[i])
            CloseHandle(ev[i]);
    }
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

// Copies src[0..len) into the body of a quoted argument.  A quote becomes
// quoteSub and CR/LF become spaces.  A trailing run of backslashes is
// doubled: left alone it would escape the closing quote.  Writes at most
// len * 2 characters.
static WCHAR* CopyQuotedBody(WCHAR* p, LPCWSTR src, int len, WCHAR quoteSub)
{
    for (int i = 0; i < len; ++i)
    {
        WCHAR c = src[i];
        if (c == L'"') c = quoteSub;
        else if (c == L'\r' || c == L'\n') c = L' ';
        *p++ = c;
    }
    for (int i = len; i > 0 && src[i - 1] == L'\\'; --i)
        *p++ = L'\\';
    return p;
}

// Appends prefix (which opens the quote, e.g. L" -A \"") then value, quoted.
static bool AppendQuoted(WCHAR* szCmd, int* pcch, LPCWSTR prefix, LPCWSTR value)
{
    const int plen = lstrlenW(prefix);
    const int vlen = value ? lstrlenW(value) : 0;
    if (vlen > kCmdMax / 2 || *pcch > kCmdMax - 1 - (plen + vlen * 2 + 1))
        return false;
    WCHAR* p = szCmd + *pcch;
    for (LPCWSTR s = prefix; *s; ) *p++ = *s++;
    p = CopyQuotedBody(p, value, vlen, L'\'');
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

// Appends one already-formed header line as -H "line".
static bool AppendHeaderLine(WCHAR* szCmd, int* pcch, LPCWSTR line, int len)
{
    if (len < 0 || len > kCmdMax / 2 || *pcch > kCmdMax - 1 - (len * 2 + 6))
        return false;
    WCHAR* p = szCmd + *pcch;
    for (LPCWSTR s = L" -H \""; *s; ) *p++ = *s++;
    p = CopyQuotedBody(p, line, len, L'\'');
    *p++ = L'"';
    *p = 0;
    *pcch = (int)(p - szCmd);
    return true;
}

// True for a "name: value" line with a non-empty name free of spaces,
// control characters and '@'.  curl reads -H @path as a file of headers.
static bool IsHeaderLine(LPCWSTR line, int len)
{
    int i = 0;
    for (; i < len && line[i] != L':'; ++i)
        if (line[i] <= L' ' || line[i] == L'@')
            return false;
    return i > 0 && i < len;
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
    //  Named pipes for the cookie jar and the request body (POST / PUT /
    //  etc.).  The server end (us) is OUTBOUND: we write, curl reads.
    // -----------------------------------------------------------------------
    WCHAR szPipeName[96]   = L"";
    WCHAR szCookiePipe[96] = L"";
    ScopedHandle hPipe;
    ScopedHandle hCookiePipe;

    // -X HEAD makes curl wait for a body. -I is a header-only request.
    const bool bHead = req.pszVerb && _wcsicmp(req.pszVerb, L"HEAD") == 0;
    const bool bHasBody = !bHead && (req.pPostData != NULL && req.cbPostData > 0);
    const bool bHasCookies = (req.pCookieJar != NULL && req.cbCookieJar > 0);

    if (bHasCookies)
    {
        hCookiePipe.Attach(CreatePrivatePipe(L"ck", req.cbCookieJar + 1,
                                             szCookiePipe, _countof(szCookiePipe)));
        if (!hCookiePipe.Valid())
            return false;
    }

    if (bHasBody)
    {
        hPipe.Attach(CreatePrivatePipe(L"body", req.cbPostData + 1,
                                       szPipeName, _countof(szPipeName)));
        if (!hPipe.Valid())
            return false;
    }

    // -----------------------------------------------------------------------
    //  Build command line.  32767 is the CreateProcess limit. Any piece
    //  that does not fit fails the launch; nothing is written past the end.
    // -----------------------------------------------------------------------
    WCHAR* szCmd = (WCHAR*)LocalAlloc(LMEM_FIXED, kCmdMax * sizeof(WCHAR));
    if (!szCmd)
        return false;
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
    // -g: [] and {} in a URL are literal, not curl glob patterns.
    bool bCmd = AppendArg(szCmd, &cch,
        L"\"%s\" -i -g --ssl-no-revoke --compressed -sS --connect-timeout 30",
        szCurl);

    // No '=' in the pipe path, so curl opens it as a cookie file. The
    // bytes stay in the pipe's memory buffer; curl reads them at startup.
    if (bCmd && bHasCookies)
        bCmd = AppendArg(szCmd, &cch, L" -b \"%s\"", szCookiePipe);

    // Verb (-I for HEAD, -X POST / -X PUT / etc. otherwise)
    const bool bCustomVerb = !bHead && VerbIsAlpha(req.pszVerb) &&
                             _wcsicmp(req.pszVerb, L"GET") != 0;
    if (bCmd && bHead)
        bCmd = AppendArg(szCmd, &cch, L" %s", L"-I");
    else if (bCmd && bCustomVerb)
        bCmd = AppendArg(szCmd, &cch, L" -X %s", req.pszVerb);

    if (bCmd && req.pszContentType && req.pszContentType[0])
        bCmd = AppendQuoted(szCmd, &cch, L" -H \"Content-Type: ", req.pszContentType);

    // A User-Agent line in the extra headers wins over -A; sending both
    // would put two User-Agent headers on the request.
    bool bHasUaHeader = false;
    for (LPCWSTR s = req.pszExtraHeaders; s && *s; ++s)
        if ((s == req.pszExtraHeaders || s[-1] == L'\n') &&
            _wcsnicmp(s, L"User-Agent:", 11) == 0)
            bHasUaHeader = true;
    if (bCmd && !bHasUaHeader && req.pszUserAgent && req.pszUserAgent[0])
        bCmd = AppendQuoted(szCmd, &cch, L" -A \"", req.pszUserAgent);

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
            if (len > 0 && !bCookie && IsHeaderLine(pLine, len))
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
        return false;
    CloseHandle(pi.hThread);

    // Cookie jar and POST body.  The waits also end if curl exits first.
    PipeJob jobs[kMaxPipes];
    int nJobs = 0;
    if (hCookiePipe.Valid())
    {
        jobs[nJobs].hPipe = hCookiePipe.Detach();
        jobs[nJobs].data  = req.pCookieJar;
        jobs[nJobs].cb    = req.cbCookieJar;
        ++nJobs;
    }
    if (hPipe.Valid())
    {
        jobs[nJobs].hPipe = hPipe.Detach();
        jobs[nJobs].data  = req.pPostData;
        jobs[nJobs].cb    = req.cbPostData;
        ++nJobs;
    }
    ServePipes(jobs, nJobs, pi.hProcess, pi.dwProcessId);

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
