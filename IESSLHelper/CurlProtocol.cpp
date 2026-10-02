#include "stdafx.h"
#include "CurlProtocol.h"
#include "CurlRunner.h"
#include "ErrorPage.h"
#include "Util.h"
#include <process.h>
#include <wininet.h>

// ===========================================================================
//  CurlProtocol
//
//  Asynchronous Pluggable Protocol (APP) handler for the https:// scheme.
//  Once Register has been called, every https request issued by the host
//  process - top-level navigation, <img>, <link>, <script>, XHR, etc. - is
//  routed through this object instead of WinInet.  We shell out to a
//  bundled curl.exe (which uses its own modern OpenSSL) and stream the
//  response back to URLMon.  Downloads are left to IE: we report the
//  server's headers and IE shows its own download dialog.
//
//  Threading:
//    Start (apartment thread)
//        +--- spawn worker, return E_PENDING
//                |
//                v
//        Worker thread
//                +--- curl -i: parse the response headers from stdout
//                +--- append body chunks to m_buf (at most kMaxQueued)
//                +--- pSink->Switch(&pd)   ; ask URLMon to call us back
//                                           ; on the apartment thread
//                v
//        Continue (apartment thread, once per Switch)
//                +--- first: ReportProgress(disposition, MIME type)
//                +--- ReportData(progress)
//                +--- at the end: ReportResult
//        Read (apartment thread, repeatedly)
//                +--- drain m_buf; E_PENDING until the worker is done
// ===========================================================================

using curlbho::Bytes;
using curlbho::CurlProcess;
using curlbho::CurlRequest;
using curlbho::MultiByteToWideAlloc;
using curlbho::ParseDecimal;
using curlbho::ScopedHandle;

namespace {

// Body bytes the worker may queue ahead of Read before it stops reading
// curl's stdout (curl then blocks on the full pipe).
static const DWORD kMaxQueued = 4 * 1024 * 1024;
// Read compacts m_buf once this much has been consumed.
static const DWORD kCompactAt = 1024 * 1024;
// Responses whose headers exceed this are treated as failures.
static const DWORD kMaxHeaderBytes = 1024 * 1024;
// Curl runs at most this many times per request (the rest are redirects).
static const int kMaxHops = 5;

// Helper used when parsing response headers — replaces a C++11 lambda so the
// file compiles with VC9 (VS2008).
static const char* MatchHdr(const char* lineStart, DWORD lineLen,
                             const char* lineEnd,
                             const char* name, DWORD nameLen)
{
    if (lineLen <= nameLen + 1) return NULL;
    if (_strnicmp(lineStart, name, nameLen) != 0) return NULL;
    if (lineStart[nameLen] != ':') return NULL;
    const char* v = lineStart + nameLen + 1;
    while (v < lineEnd && (*v == ' ' || *v == '\t')) ++v;
    return v;
}

static bool StartsWithI(const char* p, DWORD rem, const char* lit)
{
    const DWORD n = lstrlenA(lit);
    return rem >= n && _strnicmp(p, lit, n) == 0;
}

// curl --compressed has already decoded the body, so these headers describe
// bytes the caller will never see.
static bool IsEncodedSizeHeader(const char* line, DWORD lineLen, const char* lineEnd)
{
    return MatchHdr(line, lineLen, lineEnd, "Content-Encoding", 16)
        || MatchHdr(line, lineLen, lineEnd, "Transfer-Encoding", 17)
        || MatchHdr(line, lineLen, lineEnd, "Content-Length", 14);
}

static void DropEncodedSizeLines(Bytes& raw)
{
    Bytes kept;
    const char* p    = (const char*)raw.data;
    const char* pEnd = p + raw.size;
    while (p < pEnd)
    {
        const char* lineEnd = p;
        while (lineEnd < pEnd && *lineEnd != '\r' && *lineEnd != '\n')
            ++lineEnd;
        DWORD lineLen = (DWORD)(lineEnd - p);
        if (lineLen && !IsEncodedSizeHeader(p, lineLen, lineEnd))
        {
            kept.Append(p, lineLen);
            kept.AppendStr("\r\n");
        }
        p = lineEnd;
        if (p < pEnd && *p == '\r') ++p;
        if (p < pEnd && *p == '\n') ++p;
    }
    kept.AppendStr("\r\n");
    raw.Free();
    raw.Append(kept.data, kept.size);
}

// Puts "Content-Length: n" in front of the trailing blank line.
static void AppendDecodedContentLength(Bytes& raw, ULONGLONG n)
{
    if (raw.size >= 2 && raw.data[raw.size - 2] == '\r' && raw.data[raw.size - 1] == '\n')
        raw.size -= 2;
    raw.AppendStr("Content-Length: ");
    char rev[24];
    int nr = 0;
    do
    {
        rev[nr++] = (char)('0' + (char)(n % 10));
        n /= 10;
    } while (n && nr < (int)sizeof(rev));
    char digits[24];
    for (int i = 0; i < nr; ++i)
        digits[i] = rev[nr - 1 - i];
    raw.Append(digits, (DWORD)nr);
    raw.AppendStr("\r\n\r\n");
}

// Netscape cookie lines for the cookies WinInet would send for pszURL.
// curl reads these from a named pipe, so nothing is written to disk.
// Empty when there are none.
static void BuildCookieJar(LPCWSTR pszURL, Bytes& out)
{
    out.Free();
    WCHAR szHost[INTERNET_MAX_HOST_NAME_LENGTH + 1];
    DWORD cchHost = _countof(szHost);
    if (FAILED(UrlGetPartW(pszURL, szHost, &cchHost, URL_PART_HOSTNAME, 0)) || !szHost[0])
        return;

    DWORD cch = 0;
    if (!InternetGetCookieW(pszURL, NULL, NULL, &cch) || cch == 0)
        return;
    WCHAR* pszCookies = (WCHAR*)LocalAlloc(LMEM_FIXED, (cch + 1) * sizeof(WCHAR));
    if (!pszCookies)
        return;
    if (!InternetGetCookieW(pszURL, NULL, pszCookies, &cch))
        cch = 0;
    pszCookies[cch] = 0;

    for (WCHAR* p = pszCookies; *p; )
    {
        while (*p == L' ' || *p == L';') ++p;
        WCHAR* pEnd = p;
        while (*pEnd && *pEnd != L';') ++pEnd;
        WCHAR* pNext = *pEnd ? pEnd + 1 : pEnd;
        *pEnd = 0;
        while (pEnd > p && pEnd[-1] == L' ') *--pEnd = 0;

        bool ok = *p != 0;
        for (WCHAR* q = p; *q && ok; ++q)
            if (*q == L'\t' || *q == L'\r' || *q == L'\n') ok = false;
        if (ok)
        {
            WCHAR* pEq = wcschr(p, L'=');
            LPCWSTR pszValue = L"";
            if (pEq) { *pEq = 0; pszValue = pEq + 1; }

            AppendMultiByte(out, CP_ACP, szHost, -1);
            out.AppendStr("\tFALSE\t/\tFALSE\t0\t");
            AppendMultiByte(out, CP_ACP, p, -1);
            out.AppendStr("\t");
            AppendMultiByte(out, CP_ACP, pszValue, -1);
            out.AppendStr("\n");
        }
        p = pNext;
    }
    LocalFree(pszCookies);
}

// Stores one Set-Cookie header value in WinInet for pszURL.
static void StoreSetCookie(LPCWSTR pszURL, const char* v, DWORD vlen)
{
    int cch = 0;
    WCHAR* psz = MultiByteToWideAlloc(CP_ACP, v, (int)vlen, &cch);
    if (!psz) return;
    InternetSetCookieW(pszURL, NULL, psz);
    LocalFree(psz);
}

// Finds the final (non-1xx) header block in what curl -i has written so far.
// Returns false until that block's terminating blank line has arrived.
static bool FindHeaderBlock(const Bytes& b, DWORD* pStart, DWORD* pBody)
{
    const char* s = (const char*)b.data;
    DWORD start = 0;
    for (DWORD i = 0; i + 1 < b.size; ++i)
    {
        DWORD end = 0;
        if (s[i] == '\n' && s[i + 1] == '\n')
            end = i + 2;
        else if (s[i] == '\n' && s[i + 1] == '\r' && i + 2 < b.size && s[i + 2] == '\n')
            end = i + 3;
        if (!end)
            continue;
        // "HTTP/1.1 1xx" is followed by another block.
        const char* sp = (const char*)memchr(s + start, ' ', i - start);
        if (sp && sp + 1 < s + i && sp[1] == '1')
        {
            start = end;
            i = end - 1;
            continue;
        }
        *pStart = start;
        *pBody  = end;
        return true;
    }
    return false;
}

// True when v contains tok as a comma/space separated word.
static bool ContainsToken(const char* v, DWORD n, const char* tok)
{
    const DWORD tlen = lstrlenA(tok);
    for (DWORD i = 0; i + tlen <= n; ++i)
    {
        const bool edge = (i == 0) || v[i - 1] == ' ' || v[i - 1] == ',' || v[i - 1] == '\t';
        const char after = (i + tlen < n) ? v[i + tlen] : ',';
        if (edge && _strnicmp(v + i, tok, tlen) == 0 &&
            (after == ' ' || after == ',' || after == '\t'))
            return true;
    }
    return false;
}

static int HexVal(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c |= 0x20;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// Parses a Content-Disposition value: the disposition type, and filename*
// (RFC 5987, preferred) or filename.
static void ParseDisposition(const char* v, DWORD vlen,
                             bool* pAttach, CComBSTR& filename)
{
    const char* p   = v;
    const char* end = v + vlen;
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    const char* t = p;
    while (p < end && *p != ';' && *p != ' ' && *p != '\t') ++p;
    *pAttach = (p - t == 10 && _strnicmp(t, "attachment", 10) == 0);

    char plain[1024]; int cchPlain = 0;
    char ext[1024];   int cchExt   = 0;
    UINT cpExt = CP_UTF8;
    for (;;)
    {
        while (p < end && *p != ';') ++p;
        if (p >= end) break;
        ++p;
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        const char* n = p;
        while (p < end && *p != '=' && *p != ';') ++p;
        const char* nEnd = p;
        while (nEnd > n && (nEnd[-1] == ' ' || nEnd[-1] == '\t')) --nEnd;
        if (p >= end || *p != '=') continue;
        ++p;
        while (p < end && (*p == ' ' || *p == '\t')) ++p;

        char val[1024];
        int  cv = 0;
        if (p < end && *p == '"')
        {
            for (++p; p < end && *p != '"'; ++p)
            {
                if (*p == '\\' && p + 1 < end) ++p;
                if (cv < (int)sizeof(val)) val[cv++] = *p;
            }
            if (p < end) ++p;
        }
        else
        {
            for (; p < end && *p != ';'; ++p)
                if (cv < (int)sizeof(val)) val[cv++] = *p;
            while (cv > 0 && (val[cv - 1] == ' ' || val[cv - 1] == '\t')) --cv;
        }

        const int nlen = (int)(nEnd - n);
        if (nlen == 9 && _strnicmp(n, "filename*", 9) == 0)
        {
            // charset'language'percent-encoded
            int q1 = 0;
            while (q1 < cv && val[q1] != '\'') ++q1;
            int q2 = q1 + 1;
            while (q2 < cv && val[q2] != '\'') ++q2;
            if (q2 >= cv) continue;
            cpExt = (q1 == 5 && _strnicmp(val, "utf-8", 5) == 0) ? CP_UTF8
                  : (q1 == 10 && _strnicmp(val, "iso-8859-1", 10) == 0) ? 28591
                  : CP_ACP;
            cchExt = 0;
            for (int i = q2 + 1; i < cv; ++i)
            {
                int hi, lo;
                if (val[i] == '%' && i + 2 < cv &&
                    (hi = HexVal(val[i + 1])) >= 0 && (lo = HexVal(val[i + 2])) >= 0)
                {
                    ext[cchExt++] = (char)(hi * 16 + lo);
                    i += 2;
                }
                else
                    ext[cchExt++] = val[i];
            }
        }
        else if (nlen == 8 && _strnicmp(n, "filename", 8) == 0)
        {
            memcpy(plain, val, cv);
            cchPlain = cv;
        }
    }

    WCHAR wbuf[1024];
    int wlen = 0;
    if (cchExt > 0)
        wlen = MultiByteToWideChar(cpExt, 0, ext, cchExt, wbuf, _countof(wbuf) - 1);
    if (wlen <= 0 && cchPlain > 0)
    {
        // Servers send raw UTF-8 or the local code page here.
        wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, plain, cchPlain,
                                   wbuf, _countof(wbuf) - 1);
        if (wlen <= 0)
            wlen = MultiByteToWideChar(CP_ACP, 0, plain, cchPlain, wbuf, _countof(wbuf) - 1);
    }
    if (wlen > 0)
    {
        wbuf[wlen] = 0;
        filename = wbuf;
    }
}

// True for MIME types IE displays in the window.  Anything else (or no
// Content-Type at all) may end up in the download dialog, which takes over
// the navigation's bind and needs a cache file it never asked for.
static bool RendersInline(LPCWSTR mime)
{
    if (!mime || !*mime)
        return false;
    if (_wcsnicmp(mime, L"text/", 5) == 0 || _wcsnicmp(mime, L"image/", 6) == 0)
        return true;
    static const LPCWSTR kInline[] = {
        L"application/javascript", L"application/x-javascript",
        L"application/ecmascript", L"application/json",
        L"application/xml",        L"application/xhtml+xml",
        L"application/rss+xml",    L"application/atom+xml",
    };
    for (int i = 0; i < _countof(kInline); ++i)
        if (_wcsicmp(mime, kInline[i]) == 0)
            return true;
    return false;
}

// IE's User-Agent: the bind's own string, else this session's (which
// UrlMkSetSessionOption may have changed), else the registry default.
static void GetUserAgent(IInternetBindInfo* pBindInfo, CComBSTR& ua)
{
    ua.Empty();
    if (pBindInfo)
    {
        LPOLESTR psz = NULL;
        ULONG    cFetched = 0;
        if (SUCCEEDED(pBindInfo->GetBindString(BINDSTRING_USER_AGENT, &psz, 1, &cFetched))
            && cFetched > 0 && psz && psz[0])
            ua = psz;
        if (psz) CoTaskMemFree(psz);
        if (ua.Length() > 0)
            return;
    }

    // UrlMkGetSessionOption returns E_OUTOFMEMORY even when it fills the
    // buffer; cb (length including the terminator) is what says it fit.
    char  sz[1024];
    DWORD cb = 0;
    sz[0] = 0;
    UrlMkGetSessionOption(URLMON_OPTION_USERAGENT, sz, sizeof(sz), &cb, 0);
    if (cb == 0 || cb > sizeof(sz) || !sz[0])
    {
        sz[0] = 0;
        cb = sizeof(sz);
        if (FAILED(ObtainUserAgentString(0, sz, &cb)))
            return;
    }
    sz[sizeof(sz) - 1] = 0;
    WCHAR wsz[1024];
    if (MultiByteToWideChar(CP_ACP, 0, sz, -1, wsz, _countof(wsz)) > 1)
        ua = wsz;
}

// The host's IHttpNegotiate, from whichever of the sink or bind info
// offers it as a service.
static void GetHttpNegotiate(IUnknown* pSink, IUnknown* pBindInfo,
                             CComPtr<IHttpNegotiate>& out)
{
    out.Release();
    IUnknown* sources[2] = { pSink, pBindInfo };
    for (int i = 0; i < 2 && !out; ++i)
    {
        CComQIPtr<IServiceProvider> sp(sources[i]);
        if (!sp || FAILED(sp->QueryService(IID_IHttpNegotiate, IID_IHttpNegotiate,
                                           (void**)&out)))
            out.Release();
    }
}

static void SwitchTo(IInternetProtocolSink* sink)
{
    PROTOCOLDATA pd;
    ZeroMemory(&pd, sizeof(pd));
    pd.dwState  = 1;
    pd.grfFlags = PI_FORCE_ASYNC;
    sink->Switch(&pd);
}

// ---------------------------------------------------------------------------
//  CurlProtocol - the IInternetProtocol implementation.
// ---------------------------------------------------------------------------
class ATL_NO_VTABLE CurlProtocol :
    public CComObjectRootEx<CComMultiThreadModel>,
    public IInternetProtocol,
    public IWinInetHttpInfo
{
public:
    BEGIN_COM_MAP(CurlProtocol)
        COM_INTERFACE_ENTRY(IInternetProtocol)
        COM_INTERFACE_ENTRY(IInternetProtocolRoot)
        COM_INTERFACE_ENTRY(IWinInetHttpInfo)
        COM_INTERFACE_ENTRY(IWinInetInfo)
    END_COM_MAP()

    CurlProtocol() : m_bufPos(0), m_received(0), m_isError(false),
                     m_isAttachment(false), m_status(200),
                     m_contentLength((ULONGLONG)-1), m_hasEncoding(false),
                     m_hrResult(S_OK), m_hProcess(NULL), m_needFile(false),
                     m_bAbort(false), m_bHeaders(false), m_bDone(false),
                     m_bNotifyPending(false), m_bResultReported(false),
                     m_bReported(false), m_bCacheReported(false)
    {
        m_szCache[0] = 0;
        m_hRoom.Attach(CreateEventW(NULL, FALSE, FALSE, NULL));
    }

    // IInternetProtocolRoot ------------------------------------------------
    STDMETHOD(Start)(LPCWSTR szURL, IInternetProtocolSink* pSink,
                     IInternetBindInfo* pBindInfo, DWORD grfPI, HANDLE_PTR);
    STDMETHOD(Continue)(PROTOCOLDATA* pProtocolData);
    STDMETHOD(Abort)(HRESULT hrReason, DWORD);
    STDMETHOD(Terminate)(DWORD);
    STDMETHOD(Suspend)()                    { return E_NOTIMPL; }
    STDMETHOD(Resume)()                     { return E_NOTIMPL; }

    // IInternetProtocol ----------------------------------------------------
    STDMETHOD(Read)(void* pv, ULONG cb, ULONG* pcbRead);
    STDMETHOD(Seek)(LARGE_INTEGER, DWORD, ULARGE_INTEGER*) { return E_NOTIMPL; }
    STDMETHOD(LockRequest)(DWORD)           { return S_OK; }
    STDMETHOD(UnlockRequest)()              { return S_OK; }

    // IWinInetHttpInfo - IE's download code reads the response headers here.
    STDMETHOD(QueryOption)(DWORD, LPVOID, DWORD*)            { return E_NOTIMPL; }
    STDMETHOD(QueryInfo)(DWORD dwOption, LPVOID pBuffer, DWORD* pcbBuf,
                         DWORD* pdwFlags, DWORD* pdwReserved);

private:
    enum HopOutcome { kHopFollow, kHopRedirected, kHopStop };

    static unsigned __stdcall WorkerProc(void* p);
    HopOutcome FetchOneHop(WCHAR* hop, int nHop, bool* asGet,
                           Bytes& stderrBytes, DWORD* pdwExit, bool* pHaveHeaders);
    void ParseHeaders(const char* block, DWORD cb, LPCWSTR pszPage,
                      WCHAR* szLocation, DWORD cchLocation);
    void DropEncodedSizeHeaders();
    void ClearHopHeaders();
    void BeginCache();
    void WriteCache(const BYTE* p, DWORD n);
    void SealCache();
    void DiscardCache();
    bool Deliver(const BYTE* p, DWORD n);
    void Finish(DWORD dwExit, bool haveHeaders, const Bytes& stderrBytes);
    void ReportHeaders(IInternetProtocolSink* sink, const BYTE* sniff, DWORD cbSniff);
    bool FindHeader(const char* name, const char** pv, DWORD* pn) const;
    void KillCurl() { if (m_hProcess) TerminateProcess(m_hProcess, 1); }

    // The sink to call ReportResult on, or NULL when another path already
    // has (or the bind was aborted, unless evenIfAborted).  Only one caller
    // ever gets a sink.  *pHr receives m_hrResult when non-NULL.
    CComPtr<IInternetProtocolSink> ClaimResult(bool evenIfAborted, HRESULT* pHr = NULL)
    {
        CComPtr<IInternetProtocolSink> sink;
        Lock();
        if (!m_bResultReported && (evenIfAborted || !m_bAbort))
        {
            m_bResultReported = true;
            sink = m_sink;
        }
        if (pHr) *pHr = m_hrResult;
        Unlock();
        return sink;
    }

    // Call with Lock() held.  Marks a Continue as pending and returns the
    // sink to Switch on, or NULL if one is already queued.
    CComPtr<IInternetProtocolSink> TakeNotifyLocked()
    {
        CComPtr<IInternetProtocolSink> sink;
        if (!m_bNotifyPending) { m_bNotifyPending = true; sink = m_sink; }
        return sink;
    }

    CComPtr<IInternetProtocolSink> m_sink;
    CComBSTR                       m_url;
    CComBSTR                       m_verb;          // "POST"/"PUT"/etc. (empty = GET)
    CComBSTR                       m_contentType;   // Content-Type for POST/PUT
    CComBSTR                       m_extraHeaders;  // extra request headers
    CComBSTR                       m_userAgent;     // IE's User-Agent
    CComPtr<IHttpNegotiate>        m_negotiate;     // apartment thread only
    Bytes                          m_postData;      // request body for POST/PUT

    // Response body queued for Read: unread bytes are m_buf[m_bufPos..size).
    Bytes                          m_buf;
    DWORD                          m_bufPos;
    ULONGLONG                      m_received;      // body bytes queued so far
    bool                           m_isError;       // true if m_buf holds an error page

    // Response headers. Written by the worker before m_bHeaders is set.
    Bytes                          m_rawHeaders;            // final header block, CRLF lines
    CComBSTR                       m_serverContentType;     // from Content-Type:
    CComBSTR                       m_dispositionFilename;   // filename*= / filename= value
    bool                           m_isAttachment;          // disposition type is "attachment"
    DWORD                          m_status;                // final HTTP status code
    ULONGLONG                      m_contentLength;         // -1 when not sent
    bool                           m_hasEncoding;           // Content-Length is pre-decompression

    // Guarded by Lock().
    HRESULT                        m_hrResult;
    HANDLE                         m_hProcess;      // curl while it runs, else NULL
    bool                           m_needFile;      // bind asked for BINDF_NEEDFILE
    // Download dialog reads this file (it will not cache HTTPS itself).
    // Kept after a successful bind; deleted if the bind is aborted.
    WCHAR                          m_szCache[MAX_PATH];
    ScopedHandle                   m_hCache;
    bool                           m_bAbort;
    bool                           m_bHeaders;
    bool                           m_bDone;         // m_buf holds the rest of the response
    bool                           m_bNotifyPending;// a Switch is queued for Continue
    bool                           m_bResultReported;
    ScopedHandle                   m_hRoom;         // set when Read frees queue space

    bool                           m_bReported;     // apartment thread only
    bool                           m_bCacheReported;
};

void CurlProtocol::ParseHeaders(const char* block, DWORD cb, LPCWSTR pszPage,
                                WCHAR* szLocation, DWORD cchLocation)
{
    const char* p    = block;
    const char* pEnd = block + cb;
    while (p < pEnd)
    {
        const char* lineEnd = p;
        while (lineEnd < pEnd && *lineEnd != '\r' && *lineEnd != '\n')
            ++lineEnd;
        DWORD lineLen = (DWORD)(lineEnd - p);
        const char* v = NULL;
        if (lineLen)
        {
            // IE6 refuses to save an HTTPS download when these say
            // no-cache or no-store (KB 323308).  "private" is cacheable.
            const char* store = p;
            DWORD storeLen = lineLen;
            char repl[40];
            if ((v = MatchHdr(p, lineLen, lineEnd, "Cache-Control", 13)) != NULL)
            {
                DWORD vn = (DWORD)(lineEnd - v);
                if (ContainsToken(v, vn, "no-cache") || ContainsToken(v, vn, "no-store"))
                {
                    lstrcpyA(repl, "Cache-Control: private");
                    store = repl;
                    storeLen = lstrlenA(repl);
                }
            }
            else if ((v = MatchHdr(p, lineLen, lineEnd, "Pragma", 6)) != NULL)
            {
                if (ContainsToken(v, (DWORD)(lineEnd - v), "no-cache"))
                    storeLen = 0;
            }
            if (storeLen)
            {
                m_rawHeaders.Append(store, storeLen);
                m_rawHeaders.AppendStr("\r\n");
            }
        }

        if (p == block && lineLen > 5 && _strnicmp(p, "HTTP/", 5) == 0)
        {
            const char* s = p + 5;
            while (s < lineEnd && *s != ' ') ++s;
            while (s < lineEnd && *s == ' ') ++s;
            ULONGLONG code = 0;
            if (ParseDecimal(s, lineEnd, &code) && code)
                m_status = (DWORD)code;
        }
        else if ((v = MatchHdr(p, lineLen, lineEnd, "Set-Cookie", 10)) != NULL)
        {
            StoreSetCookie(pszPage, v, (DWORD)(lineEnd - v));
        }
        else if ((v = MatchHdr(p, lineLen, lineEnd, "Location", 8)) != NULL)
        {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, v, (int)(lineEnd - v),
                                          szLocation, cchLocation - 1);
            szLocation[wlen > 0 ? wlen : 0] = 0;
        }
        else if ((v = MatchHdr(p, lineLen, lineEnd, "Content-Type", 12)) != NULL)
        {
            DWORD vlen = (DWORD)(lineEnd - v);
            // Strip any "; charset=..." parameters for the MIME.
            DWORD mlen = 0;
            while (mlen < vlen && v[mlen] != ';' &&
                   v[mlen] != ' ' && v[mlen] != '\t') ++mlen;
            if (mlen > 0)
            {
                WCHAR wbuf[256];
                int wlen = MultiByteToWideChar(CP_UTF8, 0, v, mlen,
                                              wbuf, _countof(wbuf) - 1);
                if (wlen > 0) { wbuf[wlen] = 0; m_serverContentType = wbuf; }
            }
        }
        else if ((v = MatchHdr(p, lineLen, lineEnd, "Content-Length", 14)) != NULL)
        {
            ULONGLONG len = 0;
            const char* s = v;
            if (ParseDecimal(s, lineEnd, &len)) m_contentLength = len;
        }
        else if (MatchHdr(p, lineLen, lineEnd, "Content-Encoding", 16))
        {
            m_hasEncoding = true;
        }
        else if ((v = MatchHdr(p, lineLen, lineEnd, "Content-Disposition", 19)) != NULL)
        {
            ParseDisposition(v, (DWORD)(lineEnd - v),
                             &m_isAttachment, m_dispositionFilename);
        }
        p = lineEnd;
        if (p < pEnd && *p == '\r') ++p;
        if (p < pEnd && *p == '\n') ++p;
    }
    m_rawHeaders.AppendStr("\r\n");
}

void CurlProtocol::DropEncodedSizeHeaders()
{
    DropEncodedSizeLines(m_rawHeaders);
    m_contentLength = (ULONGLONG)-1;
}

void CurlProtocol::ClearHopHeaders()
{
    m_rawHeaders.Free();
    m_serverContentType.Empty();
    m_dispositionFilename.Empty();
    m_isAttachment  = false;
    m_status        = 200;
    m_contentLength = (ULONGLONG)-1;
    m_hasEncoding   = false;
    Lock();
    m_bHeaders = false;
    Unlock();
}

// Last path segment of a URL or header filename, with characters Windows
// rejects in a file name (and '#', '%', which break the name as a URL)
// turned into underscores.
static void SafeFileName(LPCWSTR src, WCHAR* dst, int cchDst)
{
    const WCHAR* base = src ? src : L"";
    const WCHAR* end = base;
    for (const WCHAR* q = base; *q && *q != L'?' && *q != L'#'; ++q)
    {
        end = q + 1;
        if (*q == L'/' || *q == L'\\') base = end;
    }
    int n = 0;
    for (const WCHAR* q = base; q < end && n < cchDst - 1; ++q)
    {
        WCHAR c = *q;
        if (c < 32 || wcschr(L"<>:\"|?*#%", c))
            c = L'_';
        dst[n++] = c;
    }
    while (n > 0 && (dst[n - 1] == L'.' || dst[n - 1] == L' '))
        --n;
    dst[n] = 0;
    if (!dst[0])
        lstrcpynW(dst, L"download", cchDst);
}

// IE's download dialog binds with BINDF_NEEDFILE | BINDF_NOWRITECACHE, so it
// never writes the cache itself.  It also labels the file with this path's
// name.  WinInet names a cache file after the URL's last segment, so the
// entry is created for a URL ending in the server's filename.
void CurlProtocol::BeginCache()
{
    if (m_szCache[0])
        return;

    WCHAR szName[MAX_PATH];
    SafeFileName(m_dispositionFilename.Length() > 0
                     ? (LPCWSTR)m_dispositionFilename : (LPCWSTR)m_url,
                 szName, _countof(szName));
    const WCHAR* ext = wcsrchr(szName, L'.');
    ext = ext ? ext + 1 : NULL;

    WCHAR szNameUrl[INTERNET_MAX_URL_LENGTH];
    DWORD cchNameUrl = _countof(szNameUrl);
    if (FAILED(UrlCombineW(m_url, szName, szNameUrl, &cchNameUrl, 0)))
        return;

    WCHAR szPath[MAX_PATH];
    const DWORD cbExpected = (m_contentLength != (ULONGLONG)-1 && m_contentLength <= MAXDWORD)
                             ? (DWORD)m_contentLength : 0;
    if (!CreateUrlCacheEntryW(szNameUrl, cbExpected, ext, szPath, 0))
        return;

    HANDLE h = CreateFileW(szPath, GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        DeleteFileW(szPath);
        return;
    }
    Lock();
    if (m_bAbort)
    {
        Unlock();
        CloseHandle(h);
        DeleteFileW(szPath);
        return;
    }
    m_hCache.Attach(h);
    lstrcpynW(m_szCache, szPath, _countof(m_szCache));
    Unlock();
}

void CurlProtocol::WriteCache(const BYTE* p, DWORD n)
{
    if (!n)
        return;
    Lock();
    if (m_hCache.Valid() && !m_bAbort)
    {
        DWORD cb = 0;
        WriteFile(m_hCache.Get(), p, n, &cb, NULL);
    }
    Unlock();
}

void CurlProtocol::SealCache()
{
    Lock();
    if (m_hCache.Valid())
    {
        FlushFileBuffers(m_hCache.Get());
        m_hCache.Close();
    }
    Unlock();
}

void CurlProtocol::DiscardCache()
{
    m_hCache.Close();
    if (m_szCache[0])
    {
        DeleteFileW(m_szCache);
        m_szCache[0] = 0;
    }
}

// Queues one body chunk for Read, waiting while kMaxQueued bytes are unread.
// False if the bind was aborted or memory ran out.
bool CurlProtocol::Deliver(const BYTE* p, DWORD n)
{
    WriteCache(p, n);
    Lock();
    if (!m_hRoom.Valid())
    {
        m_hrResult = E_OUTOFMEMORY;
        Unlock();
        return false;
    }
    while (!m_bAbort && m_buf.size - m_bufPos >= kMaxQueued)
    {
        Unlock();
        WaitForSingleObject(m_hRoom.Get(), INFINITE);
        Lock();
    }
    if (m_bAbort || !m_buf.Append(p, n))
    {
        if (!m_bAbort) m_hrResult = E_OUTOFMEMORY;
        Unlock();
        return false;
    }
    m_received += n;
    CComPtr<IInternetProtocolSink> sink = TakeNotifyLocked();
    Unlock();
    if (sink) SwitchTo(sink);
    return true;
}

void CurlProtocol::Finish(DWORD dwExit, bool haveHeaders, const Bytes& stderrBytes)
{
    SealCache();
    Lock();
    if (m_bAbort)
    {
        m_buf.Free();
        m_bufPos = 0;
        Unlock();
        return;
    }
    if (!haveHeaders)
    {
        m_buf.Free();
        m_bufPos = 0;
        curlbho::BuildErrorPage(m_buf, m_url, dwExit, stderrBytes);
        m_isError  = true;
        m_received = m_buf.size;
    }
    else if (dwExit != 0 || m_hrResult != S_OK)
    {
        // Connection dropped mid-body: IE marks the download as failed.
        if (m_hrResult == S_OK)
            m_hrResult = INET_E_DOWNLOAD_FAILURE;
        DiscardCache();
    }
    else if (m_szCache[0])
    {
        // The file is the decoded body. Replace the compressed length
        // that DropEncodedSizeHeaders removed.
        if (m_hasEncoding)
            AppendDecodedContentLength(m_rawHeaders, m_received);
        // Register the file under the real URL so IE owns and evicts it.
        int cch = 0;
        WCHAR* pszHeaders = MultiByteToWideAlloc(CP_ACP, (const char*)m_rawHeaders.data,
                                                 (int)m_rawHeaders.size, &cch);
        FILETIME zero = { 0, 0 };
        CommitUrlCacheEntryW(m_url, m_szCache, zero, zero, NORMAL_CACHE_ENTRY,
                             pszHeaders, pszHeaders ? (DWORD)cch : 0, NULL, NULL);
        if (pszHeaders) LocalFree(pszHeaders);
    }
    m_bDone = true;
    CComPtr<IInternetProtocolSink> sink = TakeNotifyLocked();
    Unlock();
    if (sink) SwitchTo(sink);
}

// Curl blocks if either pipe fills.  Stdout is read on this thread, so
// stderr has to be read at the same time.
struct StderrRead
{
    HANDLE hErr;
    Bytes* out;
};

static unsigned __stdcall StderrReadProc(void* p)
{
    StderrRead* r = static_cast<StderrRead*>(p);
    BYTE buf[4096];
    DWORD n = 0;
    while (ReadFile(r->hErr, buf, sizeof(buf), &n, NULL) && n > 0)
        r->out->Append(buf, n);
    return 0;
}

CurlProtocol::HopOutcome CurlProtocol::FetchOneHop(WCHAR* hop, int nHop, bool* asGet,
                                                       Bytes& stderrBytes, DWORD* pdwExit,
                                                       bool* pHaveHeaders)
{
    Bytes cookieJar;
    BuildCookieJar(hop, cookieJar);

    CurlRequest req;
    ZeroMemory(&req, sizeof(req));
    req.pszURL          = hop;
    req.pCookieJar      = cookieJar.size ? cookieJar.data : NULL;
    req.cbCookieJar     = cookieJar.size;
    req.pszExtraHeaders = m_extraHeaders.Length() > 0 ? (LPCWSTR)m_extraHeaders : NULL;
    req.pszUserAgent    = m_userAgent.Length() > 0 ? (LPCWSTR)m_userAgent : NULL;
    if (!*asGet)
    {
        req.pszVerb        = m_verb.Length()        > 0 ? (LPCWSTR)m_verb        : NULL;
        req.pszContentType = m_contentType.Length() > 0 ? (LPCWSTR)m_contentType : NULL;
        req.pPostData      = m_postData.data;
        req.cbPostData     = m_postData.size;
    }

    CurlProcess proc;
    if (!curlbho::StartCurl(req, &proc))
        return kHopStop;

    Lock();
    m_hProcess = proc.hProcess;
    if (m_bAbort) KillCurl();
    Unlock();

    stderrBytes.Free();
    StderrRead errRead;
    errRead.hErr = proc.hErr;
    errRead.out  = &stderrBytes;
    HANDLE hErrThread = (HANDLE)_beginthreadex(NULL, 0, StderrReadProc, &errRead, 0, NULL);
    if (!hErrThread && proc.hErr != INVALID_HANDLE_VALUE)
    {
        // Losing the error text is better than a full pipe stalling curl.
        CloseHandle(proc.hErr);
        proc.hErr = INVALID_HANDLE_VALUE;
    }

    Bytes head;
    bool  stop    = false;
    bool  follow  = false;
    bool  tooBig  = false;
    bool  toldUrlMon = false;
    BYTE  buf[65536];
    DWORD cbRead = 0;
    while (!stop && ReadFile(proc.hOut, buf, sizeof(buf), &cbRead, NULL) && cbRead > 0)
    {
        if (*pHaveHeaders)
        {
            stop = !Deliver(buf, cbRead);
            continue;
        }
        if (!head.Append(buf, cbRead) || head.size > kMaxHeaderBytes)
        {
            tooBig = stop = true;
            continue;
        }
        DWORD start = 0, body = 0;
        if (!FindHeaderBlock(head, &start, &body))
            continue;

        WCHAR szLocation[INTERNET_MAX_URL_LENGTH] = L"";
        ParseHeaders((const char*)head.data + start, body - start,
                     hop, szLocation, _countof(szLocation));

        // These are the codes IE6 follows.  Set-Cookie was stored above
        // so the next hop sees it.
        const DWORD st = m_status;
        WCHAR szTarget[INTERNET_MAX_URL_LENGTH];
        DWORD cchTarget = _countof(szTarget);
        if (szLocation[0] &&
            (st == 301 || st == 302 || st == 303 || st == 307) &&
            SUCCEEDED(UrlCombineW(hop, szLocation, szTarget, &cchTarget, 0)))
        {
            if (m_needFile && nHop + 1 < kMaxHops)
            {
                if (st != 307) *asGet = true;
                lstrcpynW(hop, szTarget, INTERNET_MAX_URL_LENGTH);
                follow = stop = true;
            }
            else
            {
                CComPtr<IInternetProtocolSink> sink = ClaimResult(false);
                if (sink)
                {
                    sink->ReportProgress(BINDSTATUS_REDIRECTING, szTarget);
                    sink->ReportResult(INET_E_REDIRECTING, 0, szTarget);
                }
                toldUrlMon = stop = true;
            }
        }
        else
        {
            *pHaveHeaders = true;
            // Not a redirect: this block is the one QueryInfo may read.
            // Drop the encoded size first, so the flag never covers a
            // buffer we are about to rebuild.
            if (m_hasEncoding)
                DropEncodedSizeHeaders();
            Lock();
            m_bHeaders = true;
            Unlock();
            if (m_needFile || m_isAttachment ||
                (st >= 200 && st < 300 && !RendersInline(m_serverContentType)))
                BeginCache();
            if (body < head.size)
                stop = !Deliver(head.data + body, head.size - body);
        }
        head.Free();
    }

    Lock();
    if (stop) KillCurl();
    m_hProcess = NULL;
    Unlock();

    // Kill first when the body was abandoned, so this wait cannot sit
    // behind a curl that is blocked on a full stdout pipe.
    if (hErrThread)
    {
        WaitForSingleObject(hErrThread, INFINITE);
        CloseHandle(hErrThread);
    }

    if (follow)
    {
        stderrBytes.Free();
        curlbho::FinishCurl(&proc);
        ClearHopHeaders();
        return kHopFollow;
    }

    const DWORD dwExit = curlbho::FinishCurl(&proc);
    *pdwExit = tooBig ? curlbho::FETCH_HEADERS_TOO_LARGE : dwExit;
    return toldUrlMon ? kHopRedirected : kHopStop;
}

unsigned __stdcall CurlProtocol::WorkerProc(void* p)
{
    CurlProtocol* self = static_cast<CurlProtocol*>(p);

    // Held until this thread has left DLL code. Release() below can drop
    // the last reference while we are still in this function.
    HMODULE hMod = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                       (LPCWSTR)(void*)CurlProtocol::WorkerProc, &hMod);

    WCHAR hop[INTERNET_MAX_URL_LENGTH];
    lstrcpynW(hop, self->m_url, _countof(hop));

    bool haveHeaders = false;
    bool redirected  = false;
    bool asGet       = false;
    DWORD dwExit     = curlbho::FETCH_LAUNCH_FAILED;
    Bytes stderrBytes;

    // One pass per redirect hop.  A document navigation reports the redirect
    // to URLMon.  A download bind (BINDF_NEEDFILE) does not follow that
    // result, so those hops are fetched here.
    for (int nHop = 0; nHop < kMaxHops && !redirected && !haveHeaders; ++nHop)
    {
        self->Lock();
        const bool aborted = self->m_bAbort;
        self->Unlock();
        if (aborted)
            break;

        const HopOutcome outcome = self->FetchOneHop(hop, nHop, &asGet, stderrBytes,
                                                     &dwExit, &haveHeaders);
        if (outcome == kHopFollow)
            continue;
        redirected = (outcome == kHopRedirected);
        break;
    }

    if (!redirected)
        self->Finish(dwExit, haveHeaders, stderrBytes);

    self->Release();      // matches AddRef in Start
    // Does not run the CRT thread cleanup: one per-thread block leaks per
    // request, which is the cost of not returning into an unloaded DLL.
    if (hMod)
        FreeLibraryAndExitThread(hMod, 0);
    return 0;
}

STDMETHODIMP CurlProtocol::Abort(HRESULT hrReason, DWORD)
{
    Lock();
    m_bAbort = true;
    KillCurl();
    SetEvent(m_hRoom.Get());
    DiscardCache();
    Unlock();
    CComPtr<IInternetProtocolSink> sink = ClaimResult(true);
    if (sink)
        sink->ReportResult(hrReason, 0, NULL);
    return S_OK;
}

STDMETHODIMP CurlProtocol::Terminate(DWORD)
{
    Lock();
    m_bAbort = true;
    KillCurl();
    SetEvent(m_hRoom.Get());
    if (!m_bDone)
        DiscardCache();
    else
        m_hCache.Close();
    m_buf.Free();
    m_bufPos = 0;
    m_sink.Release();
    Unlock();
    m_negotiate.Release();
    return S_OK;
}

STDMETHODIMP CurlProtocol::Start(LPCWSTR szURL, IInternetProtocolSink* pSink,
                                 IInternetBindInfo* pBindInfo, DWORD, HANDLE_PTR)
{
    if (!szURL || !pSink)
        return E_POINTER;
    if (!m_hRoom.Valid())
        return E_OUTOFMEMORY;

    // URLMon calls Start once per protocol object, so every other member
    // still holds its constructor value.
    m_sink = pSink;
    m_url  = szURL;

    // Extract verb, Content-Type, extra headers, and POST body from URLMon.
    if (pBindInfo)
    {
        BINDINFO bi;
        ZeroMemory(&bi, sizeof(bi));
        bi.cbSize = sizeof(bi);
        DWORD grfBINDF = 0;
        if (SUCCEEDED(pBindInfo->GetBindInfo(&grfBINDF, &bi)))
        {
            if (grfBINDF & BINDF_NEEDFILE)
                m_needFile = true;
            switch (bi.dwBindVerb)
            {
                case BINDVERB_POST:
                    m_verb = L"POST";
                    break;
                case BINDVERB_PUT:
                    m_verb = L"PUT";
                    break;
                case BINDVERB_CUSTOM:
                    if (bi.szCustomVerb && bi.szCustomVerb[0])
                        m_verb = bi.szCustomVerb;
                    break;
                default:
                    break;
            }

            // Read the request body.
            if (m_verb.Length() > 0)
            {
                if (bi.stgmedData.tymed == TYMED_HGLOBAL && bi.stgmedData.hGlobal)
                {
                    DWORD cb = (DWORD)bi.cbstgmedData;
                    if (cb == 0)
                        cb = (DWORD)GlobalSize(bi.stgmedData.hGlobal);
                    void* pv = GlobalLock(bi.stgmedData.hGlobal);
                    if (pv && cb > 0)
                        m_postData.Append(pv, cb);
                    if (pv) GlobalUnlock(bi.stgmedData.hGlobal);
                }
                else if (bi.stgmedData.tymed == TYMED_ISTREAM && bi.stgmedData.pstm)
                {
                    BYTE  buf[4096];
                    ULONG cbRead = 0;
                    while (SUCCEEDED(bi.stgmedData.pstm->Read(buf, sizeof(buf), &cbRead))
                           && cbRead > 0)
                        m_postData.Append(buf, cbRead);
                }
            }
            ReleaseBindInfo(&bi);
        }

        // Content-Type MIME type for the POST/PUT body.
        {
            LPOLESTR pszMime = NULL;
            ULONG    cFetched = 0;
            if (SUCCEEDED(pBindInfo->GetBindString(BINDSTRING_POST_DATA_MIME,
                                                   &pszMime, 1, &cFetched))
                && cFetched > 0 && pszMime)
            {
                m_contentType = pszMime;
                CoTaskMemFree(pszMime);
            }
        }

        // Any extra HTTP headers URLMon wants to forward.
        {
            LPOLESTR pszHdrs = NULL;
            ULONG    cFetched = 0;
            if (SUCCEEDED(pBindInfo->GetBindString(BINDSTRING_HEADERS,
                                                   &pszHdrs, 1, &cFetched))
                && cFetched > 0 && pszHdrs)
            {
                m_extraHeaders = pszHdrs;
                CoTaskMemFree(pszHdrs);
            }
        }
    }
    GetUserAgent(pBindInfo, m_userAgent);

    // The host adds its own request headers here: IE's Referer, XHR
    // setRequestHeader values, and so on.
    GetHttpNegotiate(pSink, pBindInfo, m_negotiate);
    if (m_negotiate)
    {
        LPWSTR  pszAdd = NULL;
        HRESULT hr = m_negotiate->BeginningTransaction(
            m_url, m_extraHeaders.Length() > 0 ? (LPCWSTR)m_extraHeaders : NULL,
            0, &pszAdd);
        if (hr == E_ABORT)
        {
            if (pszAdd) CoTaskMemFree(pszAdd);
            m_negotiate.Release();
            return E_ABORT;
        }
        if (pszAdd && pszAdd[0])
        {
            const UINT n = m_extraHeaders.Length();
            if (n > 0 && m_extraHeaders[n - 1] != L'\n')
                m_extraHeaders.Append(L"\r\n");
            m_extraHeaders.Append(pszAdd);
        }
        if (pszAdd) CoTaskMemFree(pszAdd);
    }

    AddRef();   // hold a ref for the worker
    HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, &CurlProtocol::WorkerProc,
                                            this, 0, NULL);
    if (!hThread)
    {
        Release();
        pSink->ReportResult(E_FAIL, 0, NULL);
        return E_FAIL;
    }
    CloseHandle(hThread);
    return E_PENDING;
}

// First Continue: tell URLMon what the response is.  An attachment
// disposition makes IE show its download dialog instead of rendering.
void CurlProtocol::ReportHeaders(IInternetProtocolSink* sink,
                                 const BYTE* sniffBuf, DWORD cbSniff)
{
    if (!m_isError && m_isAttachment)
        sink->ReportProgress(BINDSTATUS_CONTENTDISPOSITIONATTACH,
                             m_dispositionFilename.Length() > 0
                                 ? (LPCWSTR)m_dispositionFilename : L"");
    if (!m_isError && m_dispositionFilename.Length() > 0)
        sink->ReportProgress(BINDSTATUS_CONTENTDISPOSITIONFILENAME,
                             m_dispositionFilename);

    // Error pages are always HTML; success bodies prefer the server's
    // Content-Type, then a quick HTML sniff, then FindMimeFromData.
    LPCWSTR pszMime = L"text/html";
    LPWSTR  pszSniffed = NULL;
    if (!m_isError && m_serverContentType.Length() > 0)
    {
        pszMime = m_serverContentType;
    }
    else if (!m_isError)
    {
        // Quick HTML sniff first.  URLMon's FindMimeFromData is unreliable
        // on extension-less URLs (e.g. https://google.com/) and will often
        // return text/plain even for clearly-HTML bodies, which makes IE
        // render the raw markup.  Look for a doctype or common HTML tag in
        // the first few hundred bytes; if found, force text/html.
        bool looksLikeHtml = false;
        const char* p = (const char*)sniffBuf;
        for (DWORD i = 0; i < cbSniff; ++i)
        {
            if (p[i] != '<') continue;
            DWORD rem = cbSniff - i;
            if (StartsWithI(p + i, rem, "<!doctype") || StartsWithI(p + i, rem, "<html") ||
                StartsWithI(p + i, rem, "<head")     || StartsWithI(p + i, rem, "<body") ||
                StartsWithI(p + i, rem, "<script")   || StartsWithI(p + i, rem, "<title") ||
                StartsWithI(p + i, rem, "<meta")     || StartsWithI(p + i, rem, "<!--"))
            {
                looksLikeHtml = true;
                break;
            }
        }

        if (!looksLikeHtml && cbSniff > 0)
        {
            // Fall through to URLMon for non-HTML resources (CSS/JS/images
            // and arbitrary downloads).
            DWORD cbHint = cbSniff < 256 ? cbSniff : 256;
            if (SUCCEEDED(FindMimeFromData(NULL, m_url,
                                           (LPVOID)sniffBuf, cbHint,
                                           NULL, 0, &pszSniffed, 0)) && pszSniffed)
            {
                pszMime = pszSniffed;
            }
        }
    }

    sink->ReportProgress(BINDSTATUS_MIMETYPEAVAILABLE, pszMime);
    sink->ReportProgress(BINDSTATUS_VERIFIEDMIMETYPEAVAILABLE, pszMime);
    if (pszSniffed) CoTaskMemFree(pszSniffed);
}

STDMETHODIMP CurlProtocol::Continue(PROTOCOLDATA*)
{
    BYTE  sniffBuf[512];
    DWORD cbSniff = 0;

    Lock();
    if (!m_sink || m_bAbort)
    {
        Unlock();
        return S_OK;
    }
    CComPtr<IInternetProtocolSink> sink = m_sink;
    m_bNotifyPending = false;
    WCHAR szCache[MAX_PATH];
    szCache[0] = 0;
    if (m_szCache[0] && !m_bCacheReported)
    {
        lstrcpynW(szCache, m_szCache, _countof(szCache));
        m_bCacheReported = true;
    }
    const ULONGLONG received = m_received;
    const bool      done     = m_bDone;
    if (!m_bReported)
    {
        DWORD avail = m_buf.size - m_bufPos;
        cbSniff = avail < sizeof(sniffBuf) ? avail : sizeof(sniffBuf);
        memcpy(sniffBuf, m_buf.data + m_bufPos, cbSniff);
    }
    Unlock();

    if (szCache[0])
        sink->ReportProgress(BINDSTATUS_CACHEFILENAMEAVAILABLE, szCache);

    DWORD flags = done ? (BSCF_LASTDATANOTIFICATION | BSCF_DATAFULLYAVAILABLE)
                       : BSCF_INTERMEDIATEDATANOTIFICATION;
    if (!m_bReported)
    {
        m_bReported = true;
        if (m_negotiate && !m_isError)
        {
            int     cch = 0;
            WCHAR*  pszResp = MultiByteToWideAlloc(CP_ACP, (const char*)m_rawHeaders.data,
                                                   (int)m_rawHeaders.size, &cch);
            LPWSTR  pszReqAdd = NULL;
            HRESULT hr = m_negotiate->OnResponse(m_status, pszResp, NULL, &pszReqAdd);
            if (pszReqAdd) CoTaskMemFree(pszReqAdd);
            if (pszResp) LocalFree(pszResp);
            if (hr == E_ABORT)
            {
                Abort(E_ABORT, 0);
                return S_OK;
            }
        }
        ReportHeaders(sink, sniffBuf, cbSniff);
        flags |= BSCF_FIRSTDATANOTIFICATION;
    }

    // Progress max is the final size when known; compressed responses only
    // advertise the encoded length, so they report an unknown total.
    ULONGLONG total = 0;
    if (done)
        total = received;
    else if (!m_isError && !m_hasEncoding && m_contentLength != (ULONGLONG)-1)
        total = m_contentLength;
    sink->ReportData(flags,
                     received > MAXDWORD ? MAXDWORD : (ULONG)received,
                     total    > MAXDWORD ? MAXDWORD : (ULONG)total);

    if (done)
    {
        HRESULT hr = S_OK;
        CComPtr<IInternetProtocolSink> resultSink = ClaimResult(false, &hr);
        if (resultSink)
            resultSink->ReportResult(hr, m_status, NULL);
    }
    return S_OK;
}

STDMETHODIMP CurlProtocol::Read(void* pv, ULONG cb, ULONG* pcbRead)
{
    if (!pv || !pcbRead)
        return E_POINTER;
    *pcbRead = 0;

    Lock();
    HRESULT hr;
    DWORD avail = m_buf.size - m_bufPos;
    if (avail == 0)
    {
        hr = m_bDone ? S_FALSE : E_PENDING;
    }
    else
    {
        DWORD n = cb < avail ? cb : avail;
        memcpy(pv, m_buf.data + m_bufPos, n);
        m_bufPos += n;
        *pcbRead  = n;
        if (m_bufPos == m_buf.size)
        {
            m_buf.size = 0;
            m_bufPos   = 0;
        }
        else if (m_bufPos >= kCompactAt)
        {
            memmove(m_buf.data, m_buf.data + m_bufPos, m_buf.size - m_bufPos);
            m_buf.size -= m_bufPos;
            m_bufPos    = 0;
        }
        hr = (m_buf.size == 0 && m_bDone) ? S_FALSE : S_OK;
        SetEvent(m_hRoom.Get());
    }
    Unlock();
    return hr;
}

// Finds a header in m_rawHeaders (status line skipped).
bool CurlProtocol::FindHeader(const char* name, const char** pv, DWORD* pn) const
{
    const char* p    = (const char*)m_rawHeaders.data;
    const char* pEnd = p + m_rawHeaders.size;
    const DWORD nameLen = lstrlenA(name);
    while (p < pEnd)
    {
        const char* lineEnd = p;
        while (lineEnd < pEnd && *lineEnd != '\r') ++lineEnd;
        if (p != (const char*)m_rawHeaders.data)
        {
            if (const char* v = MatchHdr(p, (DWORD)(lineEnd - p), lineEnd, name, nameLen))
            {
                *pv = v;
                *pn = (DWORD)(lineEnd - v);
                return true;
            }
        }
        p = lineEnd + 2;
    }
    return false;
}

// HttpQueryInfo semantics: ANSI text, or a DWORD with HTTP_QUERY_FLAG_NUMBER.
STDMETHODIMP CurlProtocol::QueryInfo(DWORD dwOption, LPVOID pBuffer, DWORD* pcbBuf,
                                     DWORD* pdwFlags, DWORD*)
{
    if (!pcbBuf)
        return E_INVALIDARG;
    if (pdwFlags) *pdwFlags = 0;
    if (dwOption & HTTP_QUERY_FLAG_REQUEST_HEADERS)
    {
        SetLastError(ERROR_HTTP_HEADER_NOT_FOUND);
        return HRESULT_FROM_WIN32(ERROR_HTTP_HEADER_NOT_FOUND);
    }

    Lock();
    const bool have = m_bHeaders;
    Unlock();

    const char* v = NULL;
    DWORD       n = 0;
    char        num[16];
    if (have)
    {
        switch (dwOption & HTTP_QUERY_HEADER_MASK)
        {
            case HTTP_QUERY_RAW_HEADERS_CRLF:
                v = (const char*)m_rawHeaders.data;
                n = m_rawHeaders.size;
                break;
            case HTTP_QUERY_STATUS_CODE:
                n = wsprintfA(num, "%u", m_status);
                v = num;
                break;
            case HTTP_QUERY_CONTENT_DISPOSITION:
                FindHeader("Content-Disposition", &v, &n);
                break;
            case HTTP_QUERY_CONTENT_TYPE:
                FindHeader("Content-Type", &v, &n);
                break;
            case HTTP_QUERY_CONTENT_LENGTH:
                FindHeader("Content-Length", &v, &n);
                break;
            case HTTP_QUERY_CACHE_CONTROL:
                FindHeader("Cache-Control", &v, &n);
                break;
            case HTTP_QUERY_PRAGMA:
                FindHeader("Pragma", &v, &n);
                break;
        }
    }
    if (!v)
    {
        SetLastError(ERROR_HTTP_HEADER_NOT_FOUND);
        return HRESULT_FROM_WIN32(ERROR_HTTP_HEADER_NOT_FOUND);
    }

    if (dwOption & HTTP_QUERY_FLAG_NUMBER)
    {
        if (!pBuffer || *pcbBuf < sizeof(DWORD))
        {
            *pcbBuf = sizeof(DWORD);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
        ULONGLONG d = 0;
        const char* s = v;
        ParseDecimal(s, v + n, &d);
        *(DWORD*)pBuffer = (DWORD)d;
        *pcbBuf = sizeof(DWORD);
        return S_OK;
    }
    if (!pBuffer || *pcbBuf < n + 1)
    {
        *pcbBuf = n + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }
    memcpy(pBuffer, v, n);
    ((char*)pBuffer)[n] = 0;
    *pcbBuf = n + 1;
    return S_OK;
}

// ---------------------------------------------------------------------------
//  Class factory - a single, statically-allocated instance with a fixed
//  refcount of 2 (so AddRef/Release are no-ops).  RegisterNameSpace keeps
//  a reference but we keep the object alive for the lifetime of the DLL
//  anyway, which is correct for an in-process protocol.
// ---------------------------------------------------------------------------
class CurlProtocolFactory : public IClassFactory
{
public:
    STDMETHOD(QueryInterface)(REFIID riid, void** ppv)
    {
        if (riid == IID_IUnknown || riid == IID_IClassFactory)
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }
    STDMETHOD_(ULONG, AddRef)()  { return 2; }
    STDMETHOD_(ULONG, Release)() { return 1; }

    STDMETHOD(CreateInstance)(IUnknown* pOuter, REFIID riid, void** ppv)
    {
        if (pOuter) return CLASS_E_NOAGGREGATION;
        *ppv = NULL;
        CComObject<CurlProtocol>* pObj = NULL;
        HRESULT hr = CComObject<CurlProtocol>::CreateInstance(&pObj);
        if (FAILED(hr)) return hr;
        pObj->AddRef();
        hr = pObj->QueryInterface(riid, ppv);
        pObj->Release();
        return hr;
    }
    STDMETHOD(LockServer)(BOOL) { return S_OK; }
};

CurlProtocolFactory g_factory;
LONG                g_registerCount = 0;

// Arbitrary CLSID; only used as a registration key with URLMon.
// {6AF3E10C-5FD4-4A6B-B182-C47D8F743F5D}
const CLSID CLSID_CurlProtocol =
    { 0x6af3e10c, 0x5fd4, 0x4a6b,
      { 0xb1, 0x82, 0xc4, 0x7d, 0x8f, 0x74, 0x3f, 0x5d } };

} // namespace

// ===========================================================================
//  Public Register / Unregister.  Reference counted so multiple BHO
//  instances in the same process share a single namespace registration.
// ===========================================================================

HRESULT RegisterCurlProtocol()
{
    if (InterlockedIncrement(&g_registerCount) > 1)
        return S_OK;

    CComPtr<IInternetSession> spSession;
    HRESULT hr = CoInternetGetSession(0, &spSession, 0);
    if (SUCCEEDED(hr))
    {
        hr = spSession->RegisterNameSpace(&g_factory, CLSID_CurlProtocol,
                                          L"https", 0, NULL, 0);
    }
    if (FAILED(hr))
        InterlockedDecrement(&g_registerCount);
    return hr;
}

HRESULT UnregisterCurlProtocol()
{
    if (InterlockedDecrement(&g_registerCount) > 0)
        return S_OK;

    CComPtr<IInternetSession> spSession;
    HRESULT hr = CoInternetGetSession(0, &spSession, 0);
    if (SUCCEEDED(hr))
    {
        hr = spSession->UnregisterNameSpace(&g_factory, L"https");
    }
    return hr;
}
