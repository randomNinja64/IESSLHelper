#pragma once
#include "stdafx.h"
#include "Util.h"

// ---------------------------------------------------------------------------
// CurlRunner - launches curl.exe to perform a single HTTP(S) request.
// curl is run with -i, so stdout carries the response headers followed by
// the body.  The caller reads stdout while curl runs.  Stderr is drained
// on a side thread from launch, so a full pipe cannot stall curl.
// FinishCurl returns the exit code and that stderr.
// ---------------------------------------------------------------------------

namespace curlbho {

// Pseudo exit code returned when curl.exe could not even be launched.
// (defined in the header so it can be used as a case label in other TUs)
static const DWORD FETCH_LAUNCH_FAILED = 0xFFFFFFFE;

// Parameters passed to StartCurl.
struct CurlRequest
{
    LPCWSTR     pszURL;
    const BYTE* pCookieJar;       // if non-NULL, Netscape cookie lines served on a pipe
    DWORD       cbCookieJar;
    LPCWSTR     pszVerb;          // NULL / empty -> GET
    LPCWSTR     pszContentType;   // NULL -> not forwarded
    LPCWSTR     pszExtraHeaders;  // NULL or \r\n-delimited extra headers
    const BYTE* pPostData;        // NULL -> no request body
    DWORD       cbPostData;
};

// A running curl.exe.  hOut is the read end of its stdout.
// stderr is filled by the drain thread; hErr is not used after launch.
struct CurlProcess
{
    HANDLE hProcess;
    HANDLE hOut;
    HANDLE hErr;
    HANDLE hStderrThread;
    Bytes  errBytes;   // "stderr" is a CRT macro
};

// Launches curl and serves the cookie and POST pipes.  False if curl could
// not be started; proc is then left empty.
bool StartCurl(const CurlRequest& req, CurlProcess* proc);

// Waits for the stderr drain and for curl to exit, copies stderr into
// pStderrOut (may be NULL), and closes every handle in proc.
// Returns curl's exit code.
DWORD FinishCurl(CurlProcess* proc, Bytes* pStderrOut);

} // namespace curlbho
