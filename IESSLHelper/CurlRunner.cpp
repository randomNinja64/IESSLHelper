#include "stdafx.h"
#include "CurlRunner.h"
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

DWORD RunCurl(const CurlRequest& req)
{
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

    static LONG s_seq = 0;
    const bool bHasBody = (req.pPostData != NULL && req.cbPostData > 0);
    const bool bHasCookies = (req.pCookieJar != NULL && req.cbCookieJar > 0);

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
            return FETCH_LAUNCH_FAILED;
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
            if (hCookiePipe != INVALID_HANDLE_VALUE) CloseHandle(hCookiePipe);
            return FETCH_LAUNCH_FAILED;
        }
    }

    // -----------------------------------------------------------------------
    //  Build command line
    // -----------------------------------------------------------------------
    WCHAR szCmd[8192];
    // --compressed: ask for and transparently decode gzip/deflate/brotli.
    // URLMon forwards IE's "Accept-Encoding: gzip, deflate" via
    // BINDSTRING_HEADERS, so without this curl writes the raw
    // compressed bytes to the output file, MIME sniffing fails (the body
    // looks like application/x-gzip), and IE shows the download dialog
    // instead of rendering the page.
    // --connect-timeout bounds how long we'll wait for an unreachable
    // host; there's no overall --max-time so big downloads can take as
    // long as they need.
    int cch = wsprintfW(szCmd,
        L"\"%s\" --ssl-no-revoke --compressed -sS --connect-timeout 30",
        szCurl);

    // Dump response headers to a file so the caller can see the real
    // Content-Type and Content-Disposition the server sent, instead of
    // guessing from URL extension or URLMon's MIME sniffer.
    if (req.pszHeaderFile && req.pszHeaderFile[0])
        cch += wsprintfW(szCmd + cch, L" -D \"%s\"", req.pszHeaderFile);

    // No '=' in the pipe path, so curl opens it as a cookie file. The
    // bytes stay in the pipe's memory buffer; curl reads them at startup.
    if (bHasCookies)
    {
        if (cch + lstrlenW(szCookiePipe) + 8 >= (int)_countof(szCmd))
        {
            CloseHandle(hCookiePipe);
            if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
            return FETCH_LAUNCH_FAILED;
        }
        cch += wsprintfW(szCmd + cch, L" -b \"%s\"", szCookiePipe);
    }

    // Verb (-X POST / -X PUT / etc.)
    const bool bCustomVerb = VerbIsAlpha(req.pszVerb) &&
                             _wcsicmp(req.pszVerb, L"GET") != 0;
    if (bCustomVerb)
        cch += wsprintfW(szCmd + cch, L" -X %s", req.pszVerb);

    // Content-Type header
    if (req.pszContentType && req.pszContentType[0])
    {
        WCHAR szCT[256];
        lstrcpynW(szCT, req.pszContentType, _countof(szCT));
        for (WCHAR* p = szCT; *p; ++p)
            if (*p == L'"' || *p == L'\r' || *p == L'\n') *p = L' ';
        cch += wsprintfW(szCmd + cch, L" -H \"Content-Type: %s\"", szCT);
    }

    // Extra request headers (CRLF-delimited string from URLMon)
    if (req.pszExtraHeaders && req.pszExtraHeaders[0])
    {
        LPCWSTR pLine = req.pszExtraHeaders;
        while (*pLine)
        {
            LPCWSTR pEnd = pLine;
            while (*pEnd && *pEnd != L'\r' && *pEnd != L'\n') ++pEnd;
            int len = (int)(pEnd - pLine);
            const bool bCookie = len >= 7 && _wcsnicmp(pLine, L"Cookie:", 7) == 0;
            if (len > 0 && !bCookie && cch + len + 10 < (int)_countof(szCmd))
            {
                WCHAR szLine[512];
                int copyLen = len < (int)_countof(szLine) - 1
                            ? len : (int)_countof(szLine) - 1;
                lstrcpynW(szLine, pLine, copyLen + 1);
                for (WCHAR* p = szLine; *p; ++p)
                    if (*p == L'"') *p = L'\'';
                cch += wsprintfW(szCmd + cch, L" -H \"%s\"", szLine);
            }
            pLine = pEnd;
            while (*pLine == L'\r' || *pLine == L'\n') ++pLine;
        }
    }

    // Request body via named pipe (@path tells curl to read from the path)
    if (bHasBody)
        cch += wsprintfW(szCmd + cch, L" --data-binary \"@%s\"", szPipeName);

    // URL  (stdout is our pipe; no -o flag needed)
    wsprintfW(szCmd + cch, L" \"%s\"", req.pszURL);

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
    // read end is non-inheritable (only we read it after curl exits).
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

    const BOOL bRedirect = hNul.Valid() && hOutWrite.Valid() && hErrWrite.Valid();
    if (bRedirect)
    {
        si.dwFlags   |= STARTF_USESTDHANDLES;
        si.hStdInput  = hNul.Get();
        si.hStdOutput = hOutWrite.Get();
        si.hStdError  = hErrWrite.Get();
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL bOk = CreateProcessW(NULL, szCmd, NULL, NULL,
                              bRedirect ? TRUE : FALSE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    hNul.Close();
    hOutWrite.Close(); // close our write ends so pipes signal EOF when curl exits
    hErrWrite.Close();

    if (!bOk)
    {
        if (hCookiePipe != INVALID_HANDLE_VALUE) CloseHandle(hCookiePipe);
        if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
        return FETCH_LAUNCH_FAILED;
    }

    // Cookie file first: curl reads it at startup, before the request body.
    if (bHasCookies && hCookiePipe != INVALID_HANDLE_VALUE)
        ServePipe(hCookiePipe, pi.hProcess, req.pCookieJar, req.cbCookieJar);

    // POST body. Overlapped connect also wakes if curl exits first.
    if (bHasBody && hPipe != INVALID_HANDLE_VALUE)
        ServePipe(hPipe, pi.hProcess, req.pPostData, req.cbPostData);

    // -----------------------------------------------------------------------
    //  Drain stdout before waiting: curl may block on a full pipe buffer,
    //  which would prevent it from ever exiting.  We read until EOF (write
    //  end closed above), then wait — curl should already be done by then.
    //
    //  Small responses (<= kSpillThreshold) accumulate in pStdoutOut.
    //  Once the threshold is crossed we open pszSpillFile and write
    //  everything there instead — no memory cap, no curl error 23.
    // -----------------------------------------------------------------------
    if (req.pStdoutOut && hOutRead.Valid())
    {
        req.pStdoutOut->Free();
        if (req.pDidSpill) *req.pDidSpill = false;

        HANDLE hSpill = INVALID_HANDLE_VALUE;
        BYTE   buf[65536];
        DWORD  cbRead = 0;
        while (ReadFile(hOutRead.Get(), buf, sizeof(buf), &cbRead, NULL) && cbRead > 0)
        {
            // Switch to spill file once threshold is exceeded.
            if (hSpill == INVALID_HANDLE_VALUE &&
                req.pszSpillFile &&
                req.pStdoutOut->size + cbRead > kSpillThreshold)
            {
                hSpill = CreateFileW(req.pszSpillFile, GENERIC_WRITE, 0, NULL,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hSpill != INVALID_HANDLE_VALUE)
                {
                    // Flush already-buffered bytes to file first.
                    DWORD cbWritten = 0;
                    WriteFile(hSpill, req.pStdoutOut->data, req.pStdoutOut->size,
                              &cbWritten, NULL);
                    req.pStdoutOut->Free();
                    if (req.pDidSpill) *req.pDidSpill = true;
                }
            }

            if (hSpill != INVALID_HANDLE_VALUE)
            {
                DWORD cbWritten = 0;
                WriteFile(hSpill, buf, cbRead, &cbWritten, NULL);
            }
            else
            {
                req.pStdoutOut->Append(buf, cbRead);
            }
        }

        if (hSpill != INVALID_HANDLE_VALUE)
            CloseHandle(hSpill);
        hOutRead.Close();
    }

    DWORD dwExit = 1;
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &dwExit);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Drain the stderr pipe into the caller's buffer.
    // Curl has exited by now so the amount is small and bounded.
    if (req.pStderrOut && hErrRead.Valid())
    {
        req.pStderrOut->Free();
        BYTE buf[4096];
        DWORD cbRead = 0;
        while (ReadFile(hErrRead.Get(), buf, sizeof(buf), &cbRead, NULL) && cbRead > 0)
            req.pStderrOut->Append(buf, cbRead);
    }

    return dwExit;
}

} // namespace curlbho
