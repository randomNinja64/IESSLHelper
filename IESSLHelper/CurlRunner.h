#pragma once
#include "stdafx.h"

// ---------------------------------------------------------------------------
// CurlRunner - launches curl.exe to perform a single HTTP(S) request.
// All output goes to caller-provided files (response body and stderr);
// no parsing or buffering is done here.
// ---------------------------------------------------------------------------

namespace curlbho {

// Pseudo exit codes returned in addition to whatever curl itself returns.
// (defined in the header so they can be used as case labels in other TUs)
static const DWORD FETCH_LAUNCH_FAILED = 0xFFFFFFFE;
static const DWORD FETCH_TIMED_OUT     = 0xFFFFFFFD;

// How long we will wait for curl to complete (also bounds the pipe wait).
static const DWORD kCurlTimeoutMs      = 30000;

// Parameters passed to RunCurl.
struct CurlRequest
{
    LPCWSTR     pszURL;
    LPCWSTR     pszOutFile;
    LPCWSTR     pszStderrFile;
    LPCWSTR     pszVerb;          // NULL / empty -> GET
    LPCWSTR     pszContentType;   // NULL -> not forwarded
    LPCWSTR     pszExtraHeaders;  // NULL or \r\n-delimited extra headers
    const BYTE* pPostData;        // NULL -> no request body
    DWORD       cbPostData;
};

// Returns the curl process exit code, or FETCH_LAUNCH_FAILED / FETCH_TIMED_OUT.
DWORD RunCurl(const CurlRequest& req);

} // namespace curlbho
