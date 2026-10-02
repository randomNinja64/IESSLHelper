#pragma once
#include "stdafx.h"
#include "Util.h"

// ---------------------------------------------------------------------------
// Generates the "Could not load page" UTF-8 HTML body shown to the user when
// curl fails to retrieve a URL.
// ---------------------------------------------------------------------------

namespace curlbho {

// dwExit is either curl's process exit code or FETCH_LAUNCH_FAILED from
// CurlRunner.h.  stderrBytes is curl's captured stderr output (may be
// empty).  Result is written to out.
void BuildErrorPage(Bytes& out, LPCWSTR pszURL, DWORD dwExit,
                    const Bytes& stderrBytes);

} // namespace curlbho
