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

namespace {

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

    CurlProtocol() : m_pos(0), m_isError(false) {}

    // IInternetProtocolRoot ------------------------------------------------
    STDMETHOD(Start)(LPCWSTR szURL, IInternetProtocolSink* pSink,
                     IInternetBindInfo* pBindInfo, DWORD grfPI, HANDLE_PTR);
    STDMETHOD(Continue)(PROTOCOLDATA* pProtocolData);
    STDMETHOD(Abort)(HRESULT, DWORD)        { return S_OK; }
    STDMETHOD(Terminate)(DWORD)             { m_sink.Release(); return S_OK; }
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

    CComPtr<IInternetProtocolSink> m_sink;
    CComBSTR                       m_url;
    CComBSTR                       m_verb;          // "POST"/"PUT"/etc. (empty = GET)
    CComBSTR                       m_contentType;   // Content-Type for POST/PUT
    CComBSTR                       m_extraHeaders;  // extra request headers
    Bytes                          m_postData;      // request body for POST/PUT
    Bytes                          m_body;          // response body or error page
    DWORD                          m_pos;           // read cursor into m_body
    bool                           m_isError;       // true if m_body is an error page
};

DWORD WINAPI CurlProtocol::WorkerProc(LPVOID p)
{
    CurlProtocol* self = static_cast<CurlProtocol*>(p);

    // Fetch into a pair of temp files.
    WCHAR szDir[MAX_PATH], szBase[MAX_PATH];
    DWORD dwExit = curlbho::FETCH_LAUNCH_FAILED;
    Bytes stderrBytes;

    if (GetTempPathW(MAX_PATH, szDir) &&
        GetTempFileNameW(szDir, L"curl", 0, szBase))
    {
        DeleteFileW(szBase);
        WCHAR szOut[MAX_PATH + 8], szErr[MAX_PATH + 8];
        lstrcpynW(szOut, szBase, MAX_PATH); lstrcatW(szOut, L".out");
        lstrcpynW(szErr, szBase, MAX_PATH); lstrcatW(szErr, L".err");

        CurlRequest req;
        ZeroMemory(&req, sizeof(req));
        req.pszURL          = self->m_url;
        req.pszOutFile      = szOut;
        req.pszStderrFile   = szErr;
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
            DeleteFileW(szOut);
            DeleteFileW(szErr);
            req.pszURL = upgraded;
            DWORD dwExit2 = curlbho::RunCurl(req);
            if (dwExit2 == 0)
                dwExit = 0; // success on retry
        }

        if (dwExit == 0)
            curlbho::ReadAllBytes(szOut, self->m_body);
        if (dwExit != 0)
            curlbho::ReadAllBytes(szErr, stderrBytes);

        DeleteFileW(szOut);
        DeleteFileW(szErr);
    }

    if (dwExit != 0)
    {
        curlbho::BuildErrorPage(self->m_body, self->m_url, dwExit, stderrBytes);
        self->m_isError = true;
    }

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
    //    success bodies fall through to FindMimeFromData (URL hint + sniff).
    LPCWSTR pszMime = L"text/html";
    LPWSTR  pszSniffed = NULL;
    if (!m_isError && m_body.size > 0)
    {
        // Quick HTML sniff first.  URLMon's FindMimeFromData is unreliable
        // on extension-less URLs (e.g. https://google.com/) and will often
        // return text/plain even for clearly-HTML bodies, which makes IE
        // render the raw markup.  Look for a doctype or common HTML tag in
        // the first few hundred bytes; if found, force text/html.
        bool looksLikeHtml = false;
        DWORD cbScan = m_body.size < 512 ? m_body.size : 512;
        const char* p = (const char*)m_body.data;
        for (DWORD i = 0; i < cbScan; ++i)
        {
            if (p[i] != '<') continue;
            DWORD rem = cbScan - i;
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

        if (!looksLikeHtml)
        {
            // Fall through to URLMon for non-HTML resources (CSS/JS/images).
            DWORD cbHint = m_body.size < 256 ? m_body.size : 256;
            if (SUCCEEDED(FindMimeFromData(NULL, m_url,
                                           m_body.data, cbHint,
                                           NULL, 0, &pszSniffed, 0)) && pszSniffed)
            {
                pszMime = pszSniffed;
            }
        }
    }
    m_sink->ReportProgress(BINDSTATUS_VERIFIEDMIMETYPEAVAILABLE, pszMime);
    if (pszSniffed) CoTaskMemFree(pszSniffed);

    // 2. Tell URLMon how much data is available (everything, in one shot).
    m_sink->ReportData(BSCF_FIRSTDATANOTIFICATION
                     | BSCF_LASTDATANOTIFICATION
                     | BSCF_DATAFULLYAVAILABLE,
                       m_body.size, m_body.size);

    // 3. Mark the bind as complete.
    m_sink->ReportResult(S_OK, 200, NULL);
    return S_OK;
}

STDMETHODIMP CurlProtocol::Read(void* pv, ULONG cb, ULONG* pcbRead)
{
    if (!pv || !pcbRead)
        return E_POINTER;

    if (m_pos >= m_body.size)
    {
        *pcbRead = 0;
        return S_FALSE;
    }

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
