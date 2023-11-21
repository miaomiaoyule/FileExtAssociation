// FileExtAssociation.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <atlstr.h>
#include <ShObjIdl.h>
#include <WinError.h>
#include <comdef.h>
#include <vector>
#include <sddl.h>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

static inline DWORD WordSwap(DWORD v) { return (v >> 16) | (v << 16); }

static CString FormatUserChoiceString(const wchar_t* aExt,
    const wchar_t* aUserSid,
    const wchar_t* aProgId,
    SYSTEMTIME aTimestamp) 
{
    aTimestamp.wSecond = 0;
    aTimestamp.wMilliseconds = 0;

    FILETIME fileTime = { 0 };
    if (!::SystemTimeToFileTime(&aTimestamp, &fileTime))
    {
        return _T("");
    }

    // This string is built into Windows as part of the UserChoice hash algorithm.
    // It might vary across Windows SKUs (e.g. Windows 10 vs. Windows Server), or
    // across builds of the same SKU, but this is the only currently known
    // version. There isn't any known way of deriving it, so we assume this
    // constant value. If we are wrong, we will not be able to generate correct
    // UserChoice hashes.
    const wchar_t* userExperience =
        L"User Choice set via Windows User Experience "
        L"{D18B6DD5-6124-4341-9318-804003BAFA0B}";

    const wchar_t* userChoiceFmt =
        L"%s%s%s"
        L"%08lx"
        L"%08lx"
        L"%s";
    int userChoiceLen = _scwprintf(userChoiceFmt, aExt, aUserSid, aProgId,
        fileTime.dwHighDateTime,
        fileTime.dwLowDateTime, userExperience);
    userChoiceLen += 1;  // _scwprintf does not include the terminator

    CString strUserChoice;
    strUserChoice.GetBufferSetLength(userChoiceLen);
    _snwprintf_s(strUserChoice.GetBuffer(), userChoiceLen, _TRUNCATE, userChoiceFmt, aExt,
        aUserSid, aProgId, fileTime.dwHighDateTime,
        fileTime.dwLowDateTime, userExperience);

    ::CharLowerW(strUserChoice.GetBuffer());

    return strUserChoice.GetBuffer();
}

static std::vector<DWORD> CNG_MD5(const unsigned char* bytes, ULONG bytesLen)
{
    constexpr ULONG MD5_BYTES = 16;
    constexpr ULONG MD5_DWORDS = MD5_BYTES / sizeof(DWORD);
    std::vector<DWORD> hash;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM,
        nullptr, 0))) 
    {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        // As of Windows 7 the hash handle will manage its own object buffer when
        // pbHashObject is nullptr and cbHashObject is 0.
        if (BCRYPT_SUCCESS(::BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
            // BCryptHashData promises not to modify pbInput.
            if (BCRYPT_SUCCESS(::BCryptHashData(hHash, const_cast<unsigned char*>(bytes),
                bytesLen, 0)))
            {
                hash = std::vector<DWORD>(MD5_DWORDS);
                if (!BCRYPT_SUCCESS(::BCryptFinishHash(
                    hHash, reinterpret_cast<unsigned char*>(hash.data()),
                    MD5_DWORDS * sizeof(DWORD), 0)))
                {
                    hash = std::vector<DWORD>(MD5_DWORDS);
                }
            }
            ::BCryptDestroyHash(hHash);
        }
        ::BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return hash;
}

static CString CryptoAPI_Base64Encode(const unsigned char* bytes,
    DWORD bytesLen) 
{
    DWORD base64Len = 0;
    if (!::CryptBinaryToStringW(bytes, bytesLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        nullptr, &base64Len))
    {
        return _T("");
    }

    CString base64;
    base64.GetBufferSetLength(base64Len);
    if (!::CryptBinaryToStringW(bytes, bytesLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        base64.GetBuffer(), &base64Len)) 
    {
        return _T("");
    }

    return base64.GetBuffer();
}

static CString HashString(const wchar_t* inputString)
{
    auto inputBytes = reinterpret_cast<const unsigned char*>(inputString);
    int inputByteCount = (::lstrlenW(inputString) + 1) * sizeof(wchar_t);

    constexpr size_t DWORDS_PER_BLOCK = 2;
    constexpr size_t BLOCK_SIZE = sizeof(DWORD) * DWORDS_PER_BLOCK;
    // Incomplete blocks are ignored.
    int blockCount = inputByteCount / BLOCK_SIZE;

    if (blockCount == 0) 
    {
        return _T("");
    }

    // Compute an MD5 hash. md5[0] and md5[1] will be used as constant multipliers
    // in the scramble below.
    auto md5 = CNG_MD5(inputBytes, inputByteCount);
    if (md5.empty()) 
    {
        return _T("");
    }

    // The following loop effectively computes two checksums, scrambled like a
    // hash after every DWORD is added.

    // Constant multipliers for the scramble, one set for each DWORD in a block.
    const DWORD C0s[DWORDS_PER_BLOCK][5] = 
    {
        {md5[0] | 1, 0xCF98B111uL, 0x87085B9FuL, 0x12CEB96DuL, 0x257E1D83uL},
        {md5[1] | 1, 0xA27416F5uL, 0xD38396FFuL, 0x7C932B89uL, 0xBFA49F69uL} 
    };
    const DWORD C1s[DWORDS_PER_BLOCK][5] = 
    {
        {md5[0] | 1, 0xEF0569FBuL, 0x689B6B9FuL, 0x79F8A395uL, 0xC3EFEA97uL},
        {md5[1] | 1, 0xC31713DBuL, 0xDDCD1F0FuL, 0x59C3AF2DuL, 0x35BD1EC9uL} 
    };

    // The checksums.
    DWORD h0 = 0;
    DWORD h1 = 0;
    // Accumulated total of the checksum after each DWORD.
    DWORD h0Acc = 0;
    DWORD h1Acc = 0;

    for (int i = 0; i < blockCount; ++i)
    {
        for (size_t j = 0; j < DWORDS_PER_BLOCK; ++j)
        {
            const DWORD* C0 = C0s[j];
            const DWORD* C1 = C1s[j];

            DWORD input;
            memcpy(&input, &inputBytes[(i * DWORDS_PER_BLOCK + j) * sizeof(DWORD)],
                sizeof(DWORD));

            h0 += input;
            // Scramble 0
            h0 *= C0[0];
            h0 = WordSwap(h0) * C0[1];
            h0 = WordSwap(h0) * C0[2];
            h0 = WordSwap(h0) * C0[3];
            h0 = WordSwap(h0) * C0[4];
            h0Acc += h0;

            h1 += input;
            // Scramble 1
            h1 = WordSwap(h1) * C1[1] + h1 * C1[0];
            h1 = (h1 >> 16) * C1[2] + h1 * C1[3];
            h1 = WordSwap(h1) * C1[4] + h1;
            h1Acc += h1;
        }
    }

    DWORD hash[2] = { h0 ^ h1, h0Acc ^ h1Acc };

    return CryptoAPI_Base64Encode(reinterpret_cast<const unsigned char*>(hash),
        sizeof(hash));
}

CString GenerateUserChoiceHash(const wchar_t* aExt,
    const wchar_t* aUserSid,
    const wchar_t* aProgId,
    SYSTEMTIME aTimestamp) 
{
    auto userChoice = FormatUserChoiceString(aExt, aUserSid, aProgId, aTimestamp);
    if (!userChoice) 
    {
        return _T("");
    }

    return HashString(userChoice.GetBuffer());
}

CString GetCurrentUserStringSid() 
{
    CString strSid;
    HANDLE rawProcessToken;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY,
        &rawProcessToken)) 
    {
        return _T("");
    }

    do
    {
        DWORD userSize = 0;
        if (!(!::GetTokenInformation(rawProcessToken, TokenUser, nullptr, 0,
            &userSize) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER)) break;

        CString strUserBytes;
        strUserBytes.GetBufferSetLength(userSize);
        if (!::GetTokenInformation(rawProcessToken, TokenUser, strUserBytes.GetBuffer(),
            userSize, &userSize))
        {
            break;
        }

        wchar_t* rawSid = nullptr;
        if (!::ConvertSidToStringSidW(
            reinterpret_cast<PTOKEN_USER>(strUserBytes.GetBuffer())->User.Sid, &rawSid))
        {
            break;
        }

        strSid = rawSid;
        LocalFree(rawSid);

    } while (false);

    CloseHandle(rawProcessToken);
    
    return strSid;
}

int main()
{
    CoInitialize(NULL);

    //文件关联
    CString strExe = _T("C:\\Program Files(x86)\\2345Soft\\2345Pic\\2345PicViewer.exe");//exe路径
    CString strProID = _T("Test.png");
    CString strExt = _T(".png");
    
    //查询关联
    TCHAR szRegisteredEXE[_MAX_PATH];
    DWORD dwBufferLen = _MAX_PATH;
    HRESULT  hRes = AssocQueryString(0, ASSOCSTR_EXECUTABLE,
        _T(".png"), NULL, szRegisteredEXE, &dwBufferLen);

    //hash
    SYSTEMTIME SysTime = {};
    GetSystemTime(&SysTime);
    SysTime.wMilliseconds = 0;
    SysTime.wSecond = 0;

    CString strSid = GetCurrentUserStringSid();
    CString strHash = GenerateUserChoiceHash(strExt, strSid, strProID, SysTime);

    //write
    CRegKey RegKey;
    auto nRes = RegKey.Create(HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.png\\UserChoice\\"));
    assert(ERROR_SUCCESS == nRes);

    nRes = RegKey.SetStringValue(_T("Hash"), strHash);
    assert(ERROR_SUCCESS == nRes);
   
    nRes = RegKey.SetStringValue(_T("ProgId"), strProID);
    assert(ERROR_SUCCESS == nRes);
    
    return 0;
}