#include "stdafx.h"
#include "CurlProtocol.h"
#include "CurlRunner.h"
#include "ErrorPage.h"
#include "Util.h"

// ===========================================================================
//  CurlProtocol
//
//  Asynchronous Pluggable Protocol (APP) handler for the https:// scheme.
//  Once Register has been called, every https request issued by the host
//  process - top-level navigation, <img>, <link>, <script>, XHR, etc. - is
//  routed through this object instead of WinInet.  We shell out to a
//  bundled curl.exe (which uses its own modern OpenSSL) and stream the
//  response back to URLMon.
//
//  Threading:
//    Start (apartment thread)
//        +--- spawn worker, return E_PENDING
//                |
//                v
//        Worker thread
//                +--- run curl.exe -> body+stderr in temp files
//                +--- read body / build error page into m_body
//                +--- pSink->Switch(&pd)   ; ask URLMon to call us back
//                                           ; on the apartment thread
//                v
//        Continue (apartment thread)
//                +--- ReportProgress(MIMETYPE)
//                +--- ReportData(DATAFULLYAVAILABLE, m_body.size)
//                +--- ReportResult(S_OK)
//        Read (apartment thread, repeatedly)
//                +--- memcpy from m_body
// ===========================================================================

using curlbho::Bytes;
using curlbho::CurlRequest;
using curlbho::ScopedHandle;

namespace {

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

// ---------------------------------------------------------------------------
//  CurlProtocol - the IInternetProtocol implementation.
// ---------------------------------------------------------------------------
class ATL_NO_VTABLE CurlProtocol :
    public CComObjectRootEx<CComMultiThreadModel>,
    public IInternetProtocol,
    public IInternetProtocolInfo
{
public:
    BEGIN_COM_MAP(CurlProtocol)
        COM_INTERFACE_ENTRY(IInternetProtocol)
        COM_INTERFACE_ENTRY(IInternetProtocolRoot)
        COM_INTERFACE_ENTRY(IInternetProtocolInfo)
    END_COM_MAP()

    CurlProtocol() : m_pos(0), m_isError(false), m_bodyFileSize(0),
                     m_isAttachment(false)
    {
        m_szBodyFile[0]   = 0;
        m_szHeaderFile[0] = 0;
    }
    ~CurlProtocol() { CloseAndDeleteBodyFile(); DeleteHeaderFile(); }

    // IInternetProtocolRoot ------------------------------------------------
    STDMETHOD(Start)(LPCWSTR szURL, IInternetProtocolSink* pSink,
                     IInternetBindInfo* pBindInfo, DWORD grfPI, HANDLE_PTR);
    STDMETHOD(Continue)(PROTOCOLDATA* pProtocolData);
    STDMETHOD(Abort)(HRESULT, DWORD)        { return S_OK; }
    STDMETHOD(Terminate)(DWORD)             { CloseAndDeleteBodyFile(); DeleteHeaderFile(); m_body.Free(); m_sink.Release(); return S_OK; }
    STDMETHOD(Suspend)()                    { return E_NOTIMPL; }
    STDMETHOD(Resume)()                     { return E_NOTIMPL; }

    // IInternetProtocol ----------------------------------------------------
    STDMETHOD(Read)(void* pv, ULONG cb, ULONG* pcbRead);
    STDMETHOD(Seek)(LARGE_INTEGER, DWORD, ULARGE_INTEGER*) { return E_NOTIMPL; }
    STDMETHOD(LockRequest)(DWORD)           { return S_OK; }
    STDMETHOD(UnlockRequest)()              { return S_OK; }

    // IInternetProtocolInfo - default-action everything ---------------------
    STDMETHOD(ParseUrl)(LPCWSTR, PARSEACTION, DWORD, LPWSTR, DWORD,
                        DWORD*, DWORD)                       { return INET_E_DEFAULT_ACTION; }
    STDMETHOD(CombineUrl)(LPCWSTR, LPCWSTR, DWORD, LPWSTR, DWORD,
                          DWORD*, DWORD)                     { return INET_E_DEFAULT_ACTION; }
    STDMETHOD(CompareUrl)(LPCWSTR, LPCWSTR, DWORD)           { return INET_E_DEFAULT_ACTION; }
    STDMETHOD(QueryInfo)(LPCWSTR, QUERYOPTION, DWORD, LPVOID, DWORD,
                         DWORD*, DWORD)                      { return INET_E_DEFAULT_ACTION; }

private:
    static DWORD WINAPI WorkerProc(LPVOID p);

    void CloseAndDeleteBodyFile()
    {
        m_hBodyFile.Close();
        if (m_szBodyFile[0])
        {
            DeleteFileW(m_szBodyFile);
            m_szBodyFile[0] = 0;
        }
    }

    void DeleteHeaderFile()
    {
        if (m_szHeaderFile[0])
        {
            DeleteFileW(m_szHeaderFile);
            m_szHeaderFile[0] = 0;
        }
    }

    CComPtr<IInternetProtocolSink> m_sink;
    CComBSTR                       m_url;
    CComBSTR                       m_verb;          // "POST"/"PUT"/etc. (empty = GET)
    CComBSTR                       m_contentType;   // Content-Type for POST/PUT
    CComBSTR                       m_extraHeaders;  // extra request headers
    Bytes                          m_postData;      // request body for POST/PUT
    Bytes                          m_body;          // small response body or error page
    DWORD                          m_pos;           // read cursor into m_body
    bool                           m_isError;       // true if m_body holds an error page

    // Large response (spill) path: body is streamed from a temp file.
    WCHAR                          m_szBodyFile[MAX_PATH + 8];
    ScopedHandle                   m_hBodyFile;
    ULONGLONG                      m_bodyFileSize;

    // Response headers captured from curl (-D).
    WCHAR                          m_szHeaderFile[MAX_PATH + 8];
    CComBSTR                       m_serverContentType;     // from Content-Type:
    CComBSTR                       m_contentDisposition;    // from Content-Disposition:
    CComBSTR                       m_dispositionFilename;   // filename= / filename*= value
    bool                           m_isAttachment;          // CD says "attachment"
};

DWORD WINAPI CurlProtocol::WorkerProc(LPVOID p)
{
    CurlProtocol* self = static_cast<CurlProtocol*>(p);

    DWORD dwExit = curlbho::FETCH_LAUNCH_FAILED;
    Bytes stderrBytes;

    // Prepare a spill-file path in case the response exceeds kSpillThreshold,
    // and a header-dump file so we can read the server's real Content-Type
    // and Content-Disposition (the only reliable signal for "is this a
    // download?" — never trust MIME sniffing for that decision).
    WCHAR szOut[MAX_PATH + 8] = L"";
    WCHAR szHdr[MAX_PATH + 8] = L"";
    {
        WCHAR szDir[MAX_PATH], szBase[MAX_PATH];
        if (GetTempPathW(MAX_PATH, szDir) &&
            GetTempFileNameW(szDir, L"curl", 0, szBase))
        {
            DeleteFileW(szBase);
            lstrcpynW(szOut, szBase, MAX_PATH); lstrcatW(szOut, L".out");
            lstrcpynW(szHdr, szBase, MAX_PATH); lstrcatW(szHdr, L".hdr");
        }
    }

    bool didSpill = false;
    CurlRequest req;
    ZeroMemory(&req, sizeof(req));
    req.pszURL          = self->m_url;
    req.pStdoutOut      = &self->m_body;
    req.pszSpillFile    = szOut[0] ? szOut : NULL;
    req.pDidSpill       = &didSpill;
    req.pStderrOut      = &stderrBytes;
    req.pszHeaderFile   = szHdr[0] ? szHdr : NULL;
    req.pszVerb         = self->m_verb.Length()         > 0 ? (LPCWSTR)self->m_verb         : NULL;
    req.pszContentType  = self->m_contentType.Length()  > 0 ? (LPCWSTR)self->m_contentType  : NULL;
    req.pszExtraHeaders = self->m_extraHeaders.Length() > 0 ? (LPCWSTR)self->m_extraHeaders : NULL;
    req.pPostData       = self->m_postData.data;
    req.cbPostData      = self->m_postData.size;

    dwExit = curlbho::RunCurl(req);

    // If an http:// fetch failed, transparently retry over https://.
    // Many sites that used to serve plain HTTP now redirect or only
    // accept TLS, but legacy IE/WinInet can't complete the handshake;
    // curl can, so this gives the user a working page either way.
    if (dwExit != 0 && self->m_url &&
        (self->m_url[0] == L'h' || self->m_url[0] == L'H') &&
        _wcsnicmp(self->m_url, L"http://", 7) == 0)
    {
        CComBSTR upgraded(L"https://");
        upgraded += (BSTR)(self->m_url + 7);
        if (didSpill) { DeleteFileW(szOut); didSpill = false; }
        self->m_body.Free();
        if (szHdr[0]) DeleteFileW(szHdr);
        req.pszURL = upgraded;
        DWORD dwExit2 = curlbho::RunCurl(req);
        if (dwExit2 == 0)
            dwExit = 0; // success on retry
    }

    if (dwExit == 0)
    {
        if (didSpill)
        {
            // Large response: open the spill file for streaming in Read().
            lstrcpynW(self->m_szBodyFile, szOut, _countof(self->m_szBodyFile));
            HANDLE h = CreateFileW(szOut, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_DELETE,
                                   NULL, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                   NULL);
            if (h == INVALID_HANDLE_VALUE)
            {
                DeleteFileW(szOut);
                self->m_szBodyFile[0] = 0;
                dwExit = curlbho::FETCH_LAUNCH_FAILED;
            }
            else
            {
                self->m_hBodyFile.Attach(h);
                LARGE_INTEGER sz;
                if (GetFileSizeEx(h, &sz) && sz.QuadPart >= 0)
                    self->m_bodyFileSize = (ULONGLONG)sz.QuadPart;
            }
        }
        // else: small response is already in self->m_body — no file needed.
    }

    if (dwExit != 0)
    {
        if (didSpill) DeleteFileW(szOut);
        self->m_body.Free();
        curlbho::BuildErrorPage(self->m_body, self->m_url, dwExit, stderrBytes);
        self->m_isError = true;
    }

    // Parse the response headers (Content-Type / Content-Disposition) so
    // Continue() can use the server's authoritative values instead of
    // guessing from URL extensions or sniffed bytes.  Only the *last*
    // response block in the file matters (curl writes one block per hop
    // when -L follows redirects).
    if (!self->m_isError && szHdr[0])
    {
        HANDLE hH = CreateFileW(szHdr, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hH != INVALID_HANDLE_VALUE)
        {
            BYTE  buf[8192];
            Bytes hdrs;
            DWORD cbRead = 0;
            while (ReadFile(hH, buf, sizeof(buf), &cbRead, NULL) && cbRead > 0)
                hdrs.Append(buf, cbRead);
            CloseHandle(hH);

            // Find the start of the *final* HTTP/ status line so we ignore
            // any 3xx headers from earlier hops in a redirect chain.
            const char* pAll = (const char*)hdrs.data;
            DWORD       cb   = hdrs.size;
            const char* pStart = pAll;
            for (DWORD i = 0; i + 5 < cb; ++i)
            {
                if ((i == 0 || pAll[i-1] == '\n') &&
                    (pAll[i] == 'H' || pAll[i] == 'h') &&
                    _strnicmp(pAll + i, "HTTP/", 5) == 0)
                    pStart = pAll + i;
            }
            DWORD cbBlock = cb - (DWORD)(pStart - pAll);

            // Walk header lines.
            const char* p = pStart;
            const char* pEnd = pStart + cbBlock;
            while (p < pEnd)
            {
                const char* lineEnd = p;
                while (lineEnd < pEnd && *lineEnd != '\r' && *lineEnd != '\n')
                    ++lineEnd;
                DWORD lineLen = (DWORD)(lineEnd - p);

                if (const char* v = MatchHdr(p, lineLen, lineEnd, "Content-Type", 12))
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
                        if (wlen > 0) { wbuf[wlen] = 0; self->m_serverContentType = wbuf; }
                    }
                }
                else if (const char* v = MatchHdr(p, lineLen, lineEnd, "Content-Disposition", 19))
                {
                    DWORD vlen = (DWORD)(lineEnd - v);
                    WCHAR wbuf[1024];
                    int wlen = MultiByteToWideChar(CP_UTF8, 0, v, vlen,
                                                  wbuf, _countof(wbuf) - 1);
                    if (wlen > 0)
                    {
                        wbuf[wlen] = 0;
                        self->m_contentDisposition = wbuf;

                        // "attachment" anywhere in the value (case-insensitive).
                        for (int i = 0; i + 9 < wlen; ++i)
                        {
                            if ((wbuf[i] == L'a' || wbuf[i] == L'A') &&
                                _wcsnicmp(wbuf + i, L"attachment", 10) == 0)
                            {
                                self->m_isAttachment = true;
                                break;
                            }
                        }

                        // Pull out filename= (prefer filename*= when present;
                        // RFC 5987 encoding is not decoded — best-effort).
                        const WCHAR* pf = NULL;
                        for (int i = 0; i + 9 < wlen; ++i)
                        {
                            if ((wbuf[i] == L'f' || wbuf[i] == L'F') &&
                                _wcsnicmp(wbuf + i, L"filename", 8) == 0)
                            {
                                int j = i + 8;
                                if (j < wlen && wbuf[j] == L'*') ++j;
                                while (j < wlen && (wbuf[j] == L' ' ||
                                                    wbuf[j] == L'=' ||
                                                    wbuf[j] == L'\t')) ++j;
                                pf = wbuf + j;
                                break;
                            }
                        }
                        if (pf && *pf)
                        {
                            WCHAR fn[MAX_PATH];
                            int   fnlen = 0;
                            WCHAR quote = 0;
                            if (*pf == L'"' || *pf == L'\'') { quote = *pf; ++pf; }
                            while (*pf && fnlen < MAX_PATH - 1)
                            {
                                if (quote ? (*pf == quote) : (*pf == L';' || *pf == L' '))
                                    break;
                                fn[fnlen++] = *pf++;
                            }
                            // Skip any RFC 5987 "UTF-8''" prefix on filename*=.
                            fn[fnlen] = 0;
                            const WCHAR* pfn = fn;
                            const WCHAR* pq  = wcsstr(fn, L"''");
                            if (pq) pfn = pq + 2;
                            if (*pfn) self->m_dispositionFilename = pfn;
                        }
                    }
                }
                p = lineEnd;
                while (p < pEnd && (*p == '\r' || *p == '\n')) ++p;
            }
        }
        DeleteFileW(szHdr);
        szHdr[0] = 0;
    }
    if (szHdr[0]) DeleteFileW(szHdr);

    // Hand control back to the apartment thread.
    PROTOCOLDATA pd;
    ZeroMemory(&pd, sizeof(pd));
    pd.dwState  = 1;
    pd.grfFlags = PI_FORCE_ASYNC;
    if (self->m_sink)
        self->m_sink->Switch(&pd);

    self->Release();      // matches AddRef in Start
    return 0;
}

STDMETHODIMP CurlProtocol::Start(LPCWSTR szURL, IInternetProtocolSink* pSink,
                                 IInternetBindInfo* pBindInfo, DWORD, HANDLE_PTR)
{
    if (!szURL || !pSink)
        return E_POINTER;

    m_sink    = pSink;
    m_url     = szURL;
    m_pos     = 0;
    m_isError = false;
    m_body.Free();
    m_postData.Free();
    m_verb.Empty();
    m_contentType.Empty();
    m_extraHeaders.Empty();
    m_serverContentType.Empty();
    m_contentDisposition.Empty();
    m_dispositionFilename.Empty();
    m_isAttachment = false;
    CloseAndDeleteBodyFile();
    DeleteHeaderFile();
    m_bodyFileSize = 0;

    // Extract verb, Content-Type, extra headers, and POST body from URLMon.
    if (pBindInfo)
    {
        BINDINFO bi;
        ZeroMemory(&bi, sizeof(bi));
        bi.cbSize = sizeof(bi);
        DWORD grfBINDF = 0;
        if (SUCCEEDED(pBindInfo->GetBindInfo(&grfBINDF, &bi)))
        {
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

        // Top-level navigation vs. sub-resource detection.
    }

    AddRef();   // hold a ref for the worker
    HANDLE hThread = CreateThread(NULL, 0, &CurlProtocol::WorkerProc,
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

STDMETHODIMP CurlProtocol::Continue(PROTOCOLDATA*)
{
    if (!m_sink)
        return S_OK;

    // 1. Tell URLMon about the MIME type.  Error pages are always HTML;
    //    success bodies prefer the server's Content-Type, then a quick HTML
    //    sniff, then fall through to FindMimeFromData.
    LPCWSTR pszMime = L"text/html";
    LPWSTR  pszSniffed = NULL;
    BYTE    sniffBuf[512];
    DWORD   cbSniff = 0;

    if (!m_isError)
    {
        // Always prefer the server's Content-Type when present — it's the
        // only authoritative source.  Sniffing is for the fallback case
        // where the server didn't send one.
        if (m_serverContentType.Length() > 0)
            pszMime = m_serverContentType;

        if (m_hBodyFile.Valid() && m_bodyFileSize > 0)
        {
            // Large response (spill): read leading bytes from file, then rewind.
            DWORD cbWant = (DWORD)((m_bodyFileSize < sizeof(sniffBuf))
                                   ? m_bodyFileSize : sizeof(sniffBuf));
            if (!ReadFile(m_hBodyFile.Get(), sniffBuf, cbWant, &cbSniff, NULL))
                cbSniff = 0;
            LARGE_INTEGER zero; zero.QuadPart = 0;
            SetFilePointerEx(m_hBodyFile.Get(), zero, NULL, FILE_BEGIN);
        }
        else if (m_body.size > 0)
        {
            // Small response: sniff directly from memory.
            DWORD cbWant = m_body.size < sizeof(sniffBuf) ? m_body.size : sizeof(sniffBuf);
            memcpy(sniffBuf, m_body.data, cbWant);
            cbSniff = cbWant;
        }

        // Only sniff if the server didn't tell us anything.
        if (m_serverContentType.Length() == 0)
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
                #define _MATCHI(s) (rem >= sizeof(s)-1 && _strnicmp(p+i, s, sizeof(s)-1) == 0)
                if (_MATCHI("<!doctype") || _MATCHI("<html") ||
                    _MATCHI("<head")     || _MATCHI("<body") ||
                    _MATCHI("<script")   || _MATCHI("<title") ||
                    _MATCHI("<meta")     || _MATCHI("<!--"))
                {
                    looksLikeHtml = true;
                    break;
                }
                #undef _MATCHI
            }

            if (looksLikeHtml)
            {
                pszMime = L"text/html";
            }
            else if (cbSniff > 0)
            {
                // Fall through to URLMon for non-HTML resources (CSS/JS/images
                // and arbitrary downloads).
                DWORD cbHint = cbSniff < 256 ? cbSniff : 256;
                if (SUCCEEDED(FindMimeFromData(NULL, m_url,
                                               sniffBuf, cbHint,
                                               NULL, 0, &pszSniffed, 0)) && pszSniffed)
                {
                    pszMime = pszSniffed;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    //  Download handling.
    //
    //  We save to the download folder only when BOTH conditions hold:
    //    1. This is a top-level navigation (the user clicked / typed it),
    //       not a sub-resource fetch from inside another page.
    //    2. The server explicitly marked the response as a download via
    //       Content-Disposition: attachment.
    //
    //  Anything else — fonts, scripts, images, XHR, even an inline-served
    //  octet-stream — just streams its bytes through unchanged.
    // -----------------------------------------------------------------------
    bool isDownload = (!m_isError && m_isAttachment &&
                       (m_body.size > 0 || m_hBodyFile.Valid()));

    if (isDownload)
    {
        if (pszSniffed) { CoTaskMemFree(pszSniffed); pszSniffed = NULL; }

        // ------------------------------------------------------------------
        //  1. Derive a friendly filename.  Prefer the server's
        //     Content-Disposition filename; otherwise fall back to the URL.
        // ------------------------------------------------------------------
        WCHAR szName[MAX_PATH] = L"download";
        if (m_dispositionFilename.Length() > 0)
        {
            lstrcpynW(szName, m_dispositionFilename, MAX_PATH);
            // Strip any directory components the server tried to inject.
            WCHAR* pSlash = szName;
            for (WCHAR* q = szName; *q; ++q)
                if (*q == L'/' || *q == L'\\') pSlash = q + 1;
            if (pSlash != szName)
                lstrcpyW(szName, pSlash);
            for (WCHAR* q = szName; *q; ++q)
                if (*q == L'<' || *q == L'>' || *q == L':' || *q == L'"' ||
                    *q == L'|' || *q == L'?' || *q == L'*' || *q < 32)
                    *q = L'_';
        }
        else
        {
            LPCWSTR pu  = (LPCWSTR)m_url;
            LPCWSTR pq  = wcschr(pu, L'?');
            LPCWSTR end = pq ? pq : pu + lstrlenW(pu);
            LPCWSTR p   = end;
            while (p > pu && *(p - 1) != L'/') --p;
            int len = (int)(end - p);
            if (len > 0 && len < MAX_PATH)
            {
                lstrcpynW(szName, p, len + 1);
                for (WCHAR* q = szName; *q; ++q)
                    if (*q == L'<' || *q == L'>' || *q == L':' || *q == L'"' ||
                        *q == L'/' || *q == L'\\' || *q == L'|' || *q == L'?' ||
                        *q == L'*' || *q < 32)
                        *q = L'_';
            }
        }
        if (!szName[0]) lstrcpyW(szName, L"download");

        // ------------------------------------------------------------------
        //  2. Determine the download destination folder.
        //     Prefer IE's configured "Default Download Directory", fall back
        //     to the Desktop (works on XP through Windows 11).
        // ------------------------------------------------------------------
        WCHAR szDownloadDir[MAX_PATH] = L"";
        {
            HKEY hk;
            if (RegOpenKeyExW(HKEY_CURRENT_USER,
                    L"Software\\Microsoft\\Internet Explorer\\Main",
                    0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS)
            {
                DWORD cb   = sizeof(szDownloadDir);
                DWORD type = 0;
                RegQueryValueExW(hk, L"Default Download Directory",
                                 NULL, &type,
                                 reinterpret_cast<BYTE*>(szDownloadDir), &cb);
                RegCloseKey(hk);
            }
            if (!szDownloadDir[0])
                SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL,
                                 SHGFP_TYPE_CURRENT, szDownloadDir);
        }

        // ------------------------------------------------------------------
        //  3. Write the response to the download folder.
        //     Spilled (large) responses: move the temp file — fast, no RAM.
        //     Small (in-memory) responses: write from buffer.
        // ------------------------------------------------------------------
        WCHAR szDest[MAX_PATH];
        lstrcpynW(szDest, szDownloadDir, MAX_PATH);
        PathAppendW(szDest, szName);

        DeleteFileW(szDest);
        BOOL bOk = FALSE;
        if (m_szBodyFile[0])
        {
            m_hBodyFile.Close();
            bOk = MoveFileExW(m_szBodyFile, szDest,
                              MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);
            if (!bOk)
                bOk = CopyFileW(m_szBodyFile, szDest, FALSE);
            DeleteFileW(m_szBodyFile);
            m_szBodyFile[0] = 0;
        }
        else
        {
            ScopedHandle hDst(CreateFileW(szDest, GENERIC_WRITE, 0, NULL,
                                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL));
            if (hDst.Valid())
            {
                DWORD cbWritten = 0;
                bOk = WriteFile(hDst.Get(), m_body.data, m_body.size,
                                &cbWritten, NULL) && cbWritten == m_body.size;
            }
            if (!bOk) DeleteFileW(szDest);
        }

        // ------------------------------------------------------------------
        //  4. Build an HTML status page.  Reuse the in-memory (m_isError)
        //     read path — the content is not an error, but the mechanism
        //     is identical.
        // ------------------------------------------------------------------
        m_body.Free();
        m_isError = true;  // tell Read() to serve from m_body
        m_pos     = 0;

        // Convert wide path to UTF-8 for embedding in HTML.
        char szDestA[MAX_PATH * 3] = "";
        WideCharToMultiByte(CP_UTF8, 0, szDest, -1,
                            szDestA, sizeof(szDestA), NULL, NULL);
        char szNameA[MAX_PATH * 3] = "";
        WideCharToMultiByte(CP_UTF8, 0, szName, -1,
                            szNameA, sizeof(szNameA), NULL, NULL);

        if (bOk)
        {
            m_body.AppendStr(
                "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>Download Complete</title>"
                "<style>"
                "body{font-family:Tahoma,Arial,sans-serif;margin:40px;background:#f0f0f0}"
                ".box{background:#fff;border:1px solid #ccc;padding:24px 32px;"
                "max-width:560px;margin:auto}"
                "h2{margin-top:0;color:#006400}"
                ".path{font-family:monospace;background:#eee;padding:6px 8px;"
                "word-break:break-all;border:1px solid #ccc}"
                "</style></head><body><div class='box'>"
                "<h2>Download complete</h2>"
                "<p><b>File:</b> ");
            m_body.AppendStr(szNameA);
            m_body.AppendStr(
                "</p>"
                "<p><b>Saved to:</b></p>"
                "<div class='path'>");
            m_body.AppendStr(szDestA);
            m_body.AppendStr(
                "</div>"
                "</div></body></html>");
        }
        else
        {
            m_body.AppendStr(
                "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>Download Failed</title></head><body>"
                "<h2>Download failed</h2>"
                "<p>The file was downloaded to a temporary location "
                "but could not be moved to the download folder.</p>"
                "<p>Temporary path: ");
            m_body.AppendStr(szDestA);
            m_body.AppendStr("</p></body></html>");
        }

        pszMime = L"text/html";
    }

    m_sink->ReportProgress(BINDSTATUS_VERIFIEDMIMETYPEAVAILABLE, pszMime);
    if (pszSniffed) CoTaskMemFree(pszSniffed);

    // 2. Tell URLMon how much data is available.
    ULONG cbTotal = m_isError ? m_body.size
        : m_hBodyFile.Valid() ? (m_bodyFileSize > MAXDWORD ? MAXDWORD : (ULONG)m_bodyFileSize)
        : m_body.size;

    m_sink->ReportData(BSCF_FIRSTDATANOTIFICATION
                     | BSCF_LASTDATANOTIFICATION
                     | BSCF_DATAFULLYAVAILABLE,
                       cbTotal, cbTotal);

    // 3. Mark the bind as complete.
    m_sink->ReportResult(S_OK, 200, NULL);
    return S_OK;
}

STDMETHODIMP CurlProtocol::Read(void* pv, ULONG cb, ULONG* pcbRead)
{
    if (!pv || !pcbRead)
        return E_POINTER;
    *pcbRead = 0;

    // Large spill response: stream from the temp file.
    if (!m_isError && m_hBodyFile.Valid())
    {
        DWORD cbRead = 0;
        if (!ReadFile(m_hBodyFile.Get(), pv, cb, &cbRead, NULL))
            return S_FALSE;
        *pcbRead = cbRead;
        return (cbRead == 0) ? S_FALSE : S_OK;
    }

    // In-memory path: error pages and small responses.
    if (m_pos >= m_body.size)
        return S_FALSE;
    DWORD avail  = m_body.size - m_pos;
    DWORD toCopy = (cb < avail) ? cb : avail;
    memcpy(pv, m_body.data + m_pos, toCopy);
    m_pos    += toCopy;
    *pcbRead  = toCopy;
    return (m_pos < m_body.size) ? S_OK : S_FALSE;
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
    if (SUCCEEDED(hr))
    {
        // Also intercept http:// so we can fall back to https when an
        // http fetch fails (many legacy sites now require TLS).
        HRESULT hr2 = spSession->RegisterNameSpace(&g_factory, CLSID_CurlProtocol,
                                                   L"http", 0, NULL, 0);
        (void)hr2; // non-fatal if http registration fails
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
        spSession->UnregisterNameSpace(&g_factory, L"http");
        hr = spSession->UnregisterNameSpace(&g_factory, L"https");
    }
    return hr;
}
