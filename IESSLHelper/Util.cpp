#include "stdafx.h"
#include "Util.h"

namespace curlbho {

const DWORD kMaxResponseBytes = 64 * 1024 * 1024;   // 64 MiB

bool ReadAllBytes(LPCWSTR pszPath, Bytes& out)
{
    out.Free();

    ScopedHandle h(CreateFileW(pszPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL));
    if (!h.Valid())
        return false;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h.Get(), &sz) ||
        sz.QuadPart < 0 || sz.QuadPart > kMaxResponseBytes)
        return false;

    DWORD cb = (DWORD)sz.QuadPart;
    if (!out.Reserve(cb))
        return false;
    if (cb == 0)
        return true;

    DWORD r = 0;
    if (!ReadFile(h.Get(), out.data, cb, &r, NULL) || r != cb)
    {
        out.Free();
        return false;
    }
    return true;
}

} // namespace curlbho
