#include "stdafx.h"
#include "BHO.h"
#include "CurlProtocol.h"

extern "C" const CLSID CLSID_IESSLHelper =
    { 0x6af3e10b, 0x5fd4, 0x4a6b,
      { 0xb1, 0x82, 0xc4, 0x7d, 0x8f, 0x74, 0x3f, 0x5c } };

// ---------------------------------------------------------------------------
// IObjectWithSite::SetSite
//
// Called by IE with the browser's IUnknown on load and with NULL on unload.
// We use it as a place to plug / unplug the curl-backed pluggable protocol
// handler that does all the real work.
// ---------------------------------------------------------------------------
STDMETHODIMP CBrowserHelperObject::SetSite(IUnknown* pUnkSite)
{
    HRESULT hr = IObjectWithSiteImpl<CBrowserHelperObject>::SetSite(pUnkSite);
    if (FAILED(hr))
        return hr;

    if (pUnkSite && !m_bRegistered)
    {
        if (SUCCEEDED(RegisterCurlProtocol()))
            m_bRegistered = true;
    }
    else if (!pUnkSite && m_bRegistered)
    {
        UnregisterCurlProtocol();
        m_bRegistered = false;
    }
    return S_OK;
}