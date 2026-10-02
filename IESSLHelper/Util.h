#pragma once
#include "stdafx.h"

// ---------------------------------------------------------------------------
// Small Win32-only helpers shared by the rest of the BHO.  No STL.
// ---------------------------------------------------------------------------

namespace curlbho {

// ---------------------------------------------------------------------------
// ScopedHandle - RAII for Win32 HANDLEs.
// ---------------------------------------------------------------------------
class ScopedHandle
{
public:
    ScopedHandle(HANDLE h = INVALID_HANDLE_VALUE) : m_h(h) {}
    ~ScopedHandle() { Close(); }

    HANDLE Get()   const { return m_h; }
    bool   Valid() const { return m_h != NULL && m_h != INVALID_HANDLE_VALUE; }
    void   Close() { if (Valid()) CloseHandle(m_h); m_h = INVALID_HANDLE_VALUE; }
    void   Attach(HANDLE h) { Close(); m_h = h; }
    HANDLE Detach() { HANDLE h = m_h; m_h = INVALID_HANDLE_VALUE; return h; }

private:
    HANDLE m_h;
    ScopedHandle(const ScopedHandle&);
    ScopedHandle& operator=(const ScopedHandle&);
};

// ---------------------------------------------------------------------------
// Bytes - tiny owning byte buffer (LocalAlloc / LocalFree).
// Uses geometric capacity growth so repeated Append() calls are amortized
// O(1); a 16 MiB body assembled from 64 KiB chunks does ~9 reallocations
// instead of ~256.
// ---------------------------------------------------------------------------
struct Bytes
{
    BYTE*  data;
    DWORD  size;
    DWORD  capacity;

    Bytes() : data(NULL), size(0), capacity(0) {}
    ~Bytes() { Free(); }

    void Free()
    {
        if (data) LocalFree(data);
        data = NULL;
        size = 0;
        capacity = 0;
    }

    // Grows size by n (> 0), growing the buffer geometrically, and returns
    // the n new, uninitialised bytes.  NULL when memory runs out.
    BYTE* Extend(DWORD n)
    {
        DWORD need = size + n;
        if (need < size) return NULL; // overflow
        if (need > capacity)
        {
            DWORD cap = capacity ? capacity : 64;
            while (cap < need)
            {
                DWORD next = cap * 2;
                if (next < cap) { cap = need; break; } // overflow -> exact
                cap = next;
            }
            BYTE* nb = (BYTE*)LocalAlloc(LMEM_FIXED, cap);
            if (!nb) return NULL;
            if (data)
            {
                memcpy(nb, data, size);
                LocalFree(data);
            }
            data = nb;
            capacity = cap;
        }
        BYTE* p = data + size;
        size = need;
        return p;
    }

    bool Append(const void* src, DWORD n)
    {
        if (!n) return true;
        BYTE* p = Extend(n);
        if (!p) return false;
        memcpy(p, src, n);
        return true;
    }

    bool AppendStr(LPCSTR s) { return Append(s, (DWORD)lstrlenA(s)); }

private:
    Bytes(const Bytes&);
    Bytes& operator=(const Bytes&);
};

// Appends src (cch characters, or -1 when NUL-terminated) converted to code
// page cp.  The terminator is never appended.
inline bool AppendMultiByte(Bytes& out, UINT cp, LPCWSTR src, int cch)
{
    if (!src) return true;
    if (cch < 0) cch = lstrlenW(src);
    if (cch == 0) return true;
    const int n = WideCharToMultiByte(cp, 0, src, cch, NULL, 0, NULL, NULL);
    if (n <= 0) return false;
    BYTE* p = out.Extend((DWORD)n);
    if (!p) return false;
    WideCharToMultiByte(cp, 0, src, cch, (char*)p, n, NULL, NULL);
    return true;
}

// src[0..cb) in code page cp as a NUL-terminated wide string of *pcch
// characters.  Free with LocalFree.  NULL when empty or out of memory.
inline WCHAR* MultiByteToWideAlloc(UINT cp, const char* src, int cb, int* pcch)
{
    *pcch = 0;
    const int cch = (src && cb > 0) ? MultiByteToWideChar(cp, 0, src, cb, NULL, 0) : 0;
    WCHAR* psz = cch > 0 ? (WCHAR*)LocalAlloc(LMEM_FIXED, (cch + 1) * sizeof(WCHAR)) : NULL;
    if (!psz)
        return NULL;
    MultiByteToWideChar(cp, 0, src, cb, psz, cch);
    psz[cch] = 0;
    *pcch = cch;
    return psz;
}

// Parses the digits at s (stopping at end) into *pv and moves s past them.
// False when s does not start with a digit.
inline bool ParseDecimal(const char*& s, const char* end, ULONGLONG* pv)
{
    const char* start = s;
    ULONGLONG v = 0;
    while (s < end && *s >= '0' && *s <= '9')
        v = v * 10 + (ULONGLONG)(*s++ - '0');
    *pv = v;
    return s > start;
}

// Appends UTF-8 (or ASCII) text with & < > " ' escaped for HTML.
inline void AppendHtmlEscaped(Bytes& out, const char* s, DWORD n)
{
    for (DWORD i = 0; i < n; ++i)
    {
        switch (s[i])
        {
            case '&':  out.AppendStr("&amp;");  break;
            case '<':  out.AppendStr("&lt;");   break;
            case '>':  out.AppendStr("&gt;");   break;
            case '"':  out.AppendStr("&quot;"); break;
            case '\'': out.AppendStr("&#39;");  break;
            default:   out.Append(s + i, 1);    break;
        }
    }
}

} // namespace curlbho
