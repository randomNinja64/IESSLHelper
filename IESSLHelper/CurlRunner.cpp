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

    const bool bHasBody = (req.pPostData != NULL && req.cbPostData > 0);
    if (bHasBody)
    {
        static LONG s_seq = 0;
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
            return FETCH_LAUNCH_FAILED;
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
    int cch = wsprintfW(szCmd, L"\"%s\" -L --ssl-no-revoke --compressed -sS", szCurl);

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
            if (len > 0 && cch + len + 10 < (int)_countof(szCmd))
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

    // Output file and URL
    wsprintfW(szCmd + cch, L" -o \"%s\" \"%s\"",
              req.pszOutFile, req.pszURL);

    // -----------------------------------------------------------------------
    //  Launch curl
    // -----------------------------------------------------------------------
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    ScopedHandle hNul(CreateFileW(L"NUL",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &sa, OPEN_EXISTING, 0, NULL));
    ScopedHandle hErr(CreateFileW(req.pszStderrFile,
        GENERIC_WRITE, FILE_SHARE_READ,
        &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL));

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    const BOOL bRedirect = hNul.Valid() && hErr.Valid();
    if (bRedirect)
    {
        si.dwFlags   |= STARTF_USESTDHANDLES;
        si.hStdInput  = hNul.Get();
        si.hStdOutput = hNul.Get();
        si.hStdError  = hErr.Get();
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL bOk = CreateProcessW(NULL, szCmd, NULL, NULL,
                              bRedirect ? TRUE : FALSE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    hNul.Close();
    hErr.Close();

    if (!bOk)
    {
        if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
        return FETCH_LAUNCH_FAILED;
    }

    // -----------------------------------------------------------------------
    //  Feed POST body through the named pipe.
    //  Overlapped ConnectNamedPipe lets us also wake up if curl exits before
    //  it opens the pipe (e.g. it prints an error and dies immediately).
    // -----------------------------------------------------------------------
    if (bHasBody && hPipe != INVALID_HANDLE_VALUE)
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
                    // Wait for curl to open the pipe or for the process to die.
                    HANDLE waitOn[2] = { hEvent, pi.hProcess };
                    DWORD dw = WaitForMultipleObjects(2, waitOn, FALSE,
                                                     kCurlTimeoutMs);
                    if (dw == WAIT_OBJECT_0)
                    {
                        DWORD transferred = 0;
                        bConnected = GetOverlappedResult(hPipe, &ov,
                                                        &transferred, FALSE);
                    }
                    else
                    {
                        CancelIo(hPipe);
                    }
                }
            }

            CloseHandle(hEvent);

            if (bConnected)
            {
                DWORD cbWritten = 0;
                WriteFile(hPipe, req.pPostData, req.cbPostData,
                          &cbWritten, NULL);
            }
        }
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }

    // -----------------------------------------------------------------------
    //  Wait for curl to finish.
    // -----------------------------------------------------------------------
    DWORD dwExit = 1;
    if (WaitForSingleObject(pi.hProcess, kCurlTimeoutMs) == WAIT_OBJECT_0)
        GetExitCodeProcess(pi.hProcess, &dwExit);
    else
    {
        TerminateProcess(pi.hProcess, 1);
        dwExit = FETCH_TIMED_OUT;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return dwExit;
}

} // namespace curlbho
