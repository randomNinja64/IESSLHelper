#pragma once
#include "stdafx.h"
#include "Util.h"

// ---------------------------------------------------------------------------
// CurlRunner - launches curl.exe to perform a single HTTP(S) request.
// Response body is piped into pStdoutOut (in memory) for small responses;
// once kSpillThreshold is exceeded it spills into pszSpillFile instead.
// Stderr is always captured via a pipe into pStderrOut.
// ---------------------------------------------------------------------------

namespace curlbho {

// Pseudo exit code returned when curl.exe could not even be launched.
// (defined in the header so it can be used as a case label in other TUs)
static const DWORD FETCH_LAUNCH_FAILED = 0xFFFFFFFE;

// Responses smaller than this stay in pStdoutOut (in memory).
// Larger responses spill to pszSpillFile so downloads don't hit a cap.
static const DWORD kSpillThreshold = 16777216; // 16 MiB

// Parameters passed to RunCurl.
struct CurlRequest
{
    LPCWSTR     pszURL;
    Bytes*      pStdoutOut;       // receives body when response <= kSpillThreshold
    LPCWSTR     pszSpillFile;     // if non-NULL, large responses are written here instead
    bool*       pDidSpill;        // out: set to true if pszSpillFile was used
    Bytes*      pStderrOut;       // receives stderr bytes; may be NULL
    LPCWSTR     pszHeaderFile;    // if non-NULL, response headers are dumped here (-D)
    const BYTE* pCookieJar;      // if non-NULL, Netscape cookie lines served on a pipe
    DWORD       cbCookieJar;
    LPCWSTR     pszVerb;          // NULL / empty -> GET
    LPCWSTR     pszContentType;   // NULL -> not forwarded
    LPCWSTR     pszExtraHeaders;  // NULL or \r\n-delimited extra headers
    const BYTE* pPostData;        // NULL -> no request body
    DWORD       cbPostData;
};

// Returns the curl process exit code, or FETCH_LAUNCH_FAILED.
DWORD RunCurl(const CurlRequest& req);

} // namespace curlbho
