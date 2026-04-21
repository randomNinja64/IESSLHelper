#pragma once
#include "stdafx.h"

// ---------------------------------------------------------------------------
// CurlProtocol
//
// Asynchronous Pluggable Protocol (APP) handler that intercepts every
// https:// request issued by the host process (top-level navigation as well
// as <img>, <link>, <script>, XHR, etc.) and serves the response by shelling
// out to a bundled curl.exe.
//
// Register/Unregister are reference-counted: each BHO instance calls
// Register on SetSite(non-null) and Unregister on SetSite(null), but the
// underlying namespace registration is created on the first call and torn
// down on the last.
// ---------------------------------------------------------------------------

HRESULT RegisterCurlProtocol();
HRESULT UnregisterCurlProtocol();
