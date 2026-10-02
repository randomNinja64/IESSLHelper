#pragma once
#include "stdafx.h"

// ---------------------------------------------------------------------------
// CLSID for the IESSLHelper COM object
// {6AF3E10B-5FD4-4A6B-B182-C47D8F743F5C}
// ---------------------------------------------------------------------------
extern "C" const CLSID CLSID_IESSLHelper;

// ---------------------------------------------------------------------------
// CBrowserHelperObject
//
// Minimal BHO whose only job is to register a curl-backed pluggable
// protocol handler for https:// for the lifetime of the IE process it is
// loaded into.  All real work happens in CurlProtocol.cpp.
//
//   SetSite(non-null) -> RegisterCurlProtocol()
//   SetSite(null)     -> UnregisterCurlProtocol()
// ---------------------------------------------------------------------------
class ATL_NO_VTABLE CBrowserHelperObject
    : public CComObjectRootEx<CComSingleThreadModel>
    , public CComCoClass<CBrowserHelperObject, &CLSID_IESSLHelper>
    , public IObjectWithSiteImpl<CBrowserHelperObject>
{
public:
    CBrowserHelperObject() : m_bRegistered(false) {}

    DECLARE_PROTECT_FINAL_CONSTRUCT()
    DECLARE_NOT_AGGREGATABLE(CBrowserHelperObject)
    DECLARE_NO_REGISTRY()

    BEGIN_COM_MAP(CBrowserHelperObject)
        COM_INTERFACE_ENTRY(IObjectWithSite)
    END_COM_MAP()

    STDMETHOD(SetSite)(IUnknown* pUnkSite);

private:
    bool m_bRegistered;
};

OBJECT_ENTRY_AUTO(CLSID_IESSLHelper, CBrowserHelperObject)