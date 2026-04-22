#pragma once
#include "stdafx.h"

// ---------------------------------------------------------------------------
// Small Win32-only helpers shared by the rest of the BHO.  No CRT, no STL.
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

    // Append n bytes, growing the buffer geometrically.
    bool Append(const void* src, DWORD n)
    {
        if (!n) return true;
        DWORD need = size + n;
        if (need < size) return false; // overflow
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
            if (!nb) return false;
            if (data)
            {
                memcpy(nb, data, size);
                LocalFree(data);
            }
            data = nb;
            capacity = cap;
        }
        memcpy(data + size, src, n);
        size += n;
        return true;
    }

    bool AppendStr(LPCSTR s) { return Append(s, (DWORD)lstrlenA(s)); }

private:
    Bytes(const Bytes&);
    Bytes& operator=(const Bytes&);
};

} // namespace curlbho
