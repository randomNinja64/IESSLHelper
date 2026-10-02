#pragma once
#include "stdafx.h"
#include "Util.h"

// ---------------------------------------------------------------------------
// CurlRunner - launches curl.exe to perform a single HTTP(S) request.
// curl is run with -i, so stdout carries the response headers followed by
// the body.  The caller reads stdout and stderr together while curl
// runs, then calls FinishCurl for the exit code.
// ---------------------------------------------------------------------------

namespace curlbho {

// Pseudo exit code returned when curl.exe could not even be launched.
// (defined in the header so it can be used as a case label in other TUs)
static const DWORD FETCH_LAUNCH_FAILED    = 0xFFFFFFFE;
static const DWORD FETCH_HEADERS_TOO_LARGE = 0xFFFFFFFD;

// Parameters passed to StartCurl.
struct CurlRequest
{
    LPCWSTR     pszURL;
    const BYTE* pCookieJar;       // if non-NULL, Netscape cookie lines served on a pipe
    DWORD       cbCookieJar;
    LPCWSTR     pszVerb;          // NULL / empty -> GET
    LPCWSTR     pszContentType;   // NULL -> not forwarded
    LPCWSTR     pszUserAgent;     // NULL -> curl's default
    LPCWSTR     pszExtraHeaders;  // NULL or \r\n-delimited extra headers
    const BYTE* pPostData;        // NULL -> no request body
    DWORD       cbPostData;
};

// A running curl.exe.  hOut is the read end of its stdout.
struct CurlProcess
{
    HANDLE hProcess;
    HANDLE hOut;
    HANDLE hErr;
};

// Launches curl and serves the cookie and POST pipes.  False if curl could
// not be started; proc is then left empty.
bool StartCurl(const CurlRequest& req, CurlProcess* proc);

// Waits for curl to exit and closes every handle in proc.  The caller
// drains stderr while curl is running.  Returns curl's exit code.
DWORD FinishCurl(CurlProcess* proc);

} // namespace curlbho
