#pragma once
#include "stdafx.h"

// ---------------------------------------------------------------------------
// Small Win32-only helpers shared by the rest of the BHO.  No CRT, no STL.
// ---------------------------------------------------------------------------

namespace curlbho {

// Maximum response size we are willing to load into memory.
extern const DWORD kMaxResponseBytes;   // 64 MiB

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

private:
    HANDLE m_h;
    ScopedHandle(const ScopedHandle&);
    ScopedHandle& operator=(const ScopedHandle&);
};

// ---------------------------------------------------------------------------
// Bytes - tiny owning byte buffer (LocalAlloc / LocalFree).
// ---------------------------------------------------------------------------
struct Bytes
{
    BYTE*  data;
    DWORD  size;

    Bytes() : data(NULL), size(0) {}
    ~Bytes() { Free(); }

    void Free()
    {
        if (data) LocalFree(data);
        data = NULL;
        size = 0;
    }

    bool Reserve(DWORD n)
    {
        Free();
        data = (BYTE*)LocalAlloc(LMEM_FIXED, n ? n : 1);
        size = data ? n : 0;
        return data != NULL;
    }

    // Append n bytes, growing the buffer.
    bool Append(const void* src, DWORD n)
    {
        if (!n) return true;
        BYTE* nb = (BYTE*)LocalAlloc(LMEM_FIXED, size + n);
        if (!nb) return false;
        if (data) memcpy(nb, data, size);
        memcpy(nb + size, src, n);
        if (data) LocalFree(data);
        data = nb;
        size += n;
        return true;
    }

    bool AppendStr(LPCSTR s) { return Append(s, (DWORD)lstrlenA(s)); }

private:
    Bytes(const Bytes&);
    Bytes& operator=(const Bytes&);
};

// Read an entire file into out, capped at kMaxResponseBytes.
bool ReadAllBytes(LPCWSTR pszPath, Bytes& out);

} // namespace curlbho
