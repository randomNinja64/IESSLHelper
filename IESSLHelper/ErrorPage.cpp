#include "stdafx.h"
#include "ErrorPage.h"
#include "CurlRunner.h"   // FETCH_LAUNCH_FAILED, FETCH_TIMED_OUT

namespace curlbho {

static void AppendUtf8(Bytes& out, LPCWSTR src)
{
    if (!src || !*src) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL);
    if (n <= 1) return;
    n -= 1;   // drop terminator
    char* tmp = (char*)LocalAlloc(LMEM_FIXED, n);
    if (!tmp) return;
    WideCharToMultiByte(CP_UTF8, 0, src, -1, tmp, n, NULL, NULL);
    out.Append(tmp, (DWORD)n);
    LocalFree(tmp);
}

static void AppendUtf8Escaped(Bytes& out, LPCWSTR src)
{
    if (!src) return;
    while (*src)
    {
        WCHAR c = *src++;
        switch (c)
        {
            case L'&':  out.AppendStr("&amp;");  break;
            case L'<':  out.AppendStr("&lt;");   break;
            case L'>':  out.AppendStr("&gt;");   break;
            case L'"':  out.AppendStr("&quot;"); break;
            case L'\'': out.AppendStr("&#39;");  break;
            default:
            {
                WCHAR pair[2] = { c, 0 };
                AppendUtf8(out, pair);
                break;
            }
        }
    }
}

static void AppendStderrEscaped(Bytes& out, const Bytes& src)
{
    for (DWORD i = 0; i < src.size; ++i)
    {
        char c = (char)src.data[i];
        switch (c)
        {
            case '<': out.AppendStr("&lt;");  break;
            case '>': out.AppendStr("&gt;");  break;
            case '&': out.AppendStr("&amp;"); break;
            default:  out.Append(&c, 1);      break;
        }
    }
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
        case FETCH_TIMED_OUT:
            pszMsg = L"curl did not finish within the 30-second timeout.";
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
    AppendUtf8Escaped(out, pszMsg);
    out.AppendStr("</p><p class=\"muted\">URL: <code>");
    AppendUtf8Escaped(out, pszURL);
    out.AppendStr("</code></p>");
    if (stderrBytes.size)
    {
        out.AppendStr("<h2>curl stderr</h2><pre>");
        AppendStderrEscaped(out, stderrBytes);
        out.AppendStr("</pre>");
    }
    out.AppendStr("<p class=\"muted\">Served by IESSLHelper.</p></body></html>");
}

} // namespace curlbho
