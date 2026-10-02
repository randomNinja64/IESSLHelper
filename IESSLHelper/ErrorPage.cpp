#include "stdafx.h"
#include "ErrorPage.h"
#include "CurlRunner.h"   // FETCH_LAUNCH_FAILED

namespace curlbho {

// src (cch characters, or -1 when NUL-terminated) as HTML-escaped UTF-8.
static void AppendEscaped(Bytes& out, LPCWSTR src, int cch)
{
    Bytes utf8;
    if (AppendMultiByte(utf8, CP_UTF8, src, cch))
        AppendHtmlEscaped(out, (const char*)utf8.data, utf8.size);
}

void BuildErrorPage(Bytes& out, LPCWSTR pszURL, DWORD dwExit,
                    const Bytes& stderrBytes)
{
    out.Free();

    LPCWSTR pszMsg;
    WCHAR   szMsg[256];
    switch (dwExit)
    {
        case FETCH_LAUNCH_FAILED:
            pszMsg = L"Failed to launch curl.exe. Make sure it exists next to "
                     L"the BHO DLL or is on PATH.";
            break;
        default:
            wsprintfW(szMsg,
                L"curl exited with code %u. See the details below for the "
                L"error message it printed.", dwExit);
            pszMsg = szMsg;
            break;
    }

    out.AppendStr(
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>Could not load page</title>"
        "<style>"
        "body{font:13px 'Segoe UI',Tahoma,sans-serif;margin:2em;color:#222;background:#fff}"
        "h1{color:#b00020;font-size:1.4em;margin:0 0 .5em}"
        "h2{font-size:1.05em;margin:1.5em 0 .3em;color:#444}"
        "code{background:#f4f4f4;padding:.1em .3em;word-break:break-all;"
        "font-family:Consolas,monospace}"
        "pre{background:#f4f4f4;border:1px solid #ddd;padding:.6em;overflow:auto;"
        "max-height:24em;white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px}"
        ".muted{color:#666;font-size:.9em}"
        "</style></head><body>"
        "<h1>Could not load page</h1><p>");
    AppendEscaped(out, pszMsg, -1);
    out.AppendStr("</p><p class=\"muted\">URL: <code>");
    AppendEscaped(out, pszURL, -1);
    out.AppendStr("</code></p>");
    if (stderrBytes.size)
    {
        // curl writes stderr in the ANSI code page; the page is UTF-8.
        int cch = 0;
        WCHAR* pszErr = MultiByteToWideAlloc(CP_ACP, (const char*)stderrBytes.data,
                                             (int)stderrBytes.size, &cch);
        out.AppendStr("<h2>curl stderr</h2><pre>");
        AppendEscaped(out, pszErr, cch);
        out.AppendStr("</pre>");
        if (pszErr) LocalFree(pszErr);
    }
    out.AppendStr("<p class=\"muted\">Served by IESSLHelper.</p></body></html>");
}

} // namespace curlbho
