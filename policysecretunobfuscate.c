#include <iostream>
#include <windows.h>
#include <wincrypt.h>

// https://stackoverflow.com/questions/17261798/converting-a-hex-string-to-a-byte-array
int char2int(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}

void hex2bin(const char* src, char* target)
{
    while (*src && src[1])
    {
        *(target++) = char2int(*src) * 16 + char2int(src[1]);
        src += 2;
    }
}

int main(int argc, char **argv)
{
    HCRYPTPROV prov, prov2;
    HCRYPTHASH hash;
    HCRYPTKEY cryptKey;
    BYTE buffer[1024];

    if (argc != 2) {
        return 1;
    }

    char* input = argv[1];

    if (input[0] != '8' || input[1] != '9') {
        return 1;
    }

    char* output = (char*)malloc(strlen(input) / 2);
    if (output == NULL) {
        return 1;
    }

    // Convert to bytes
    hex2bin(input, output);

    // Get data length
    DWORD len = *(DWORD*)(output + 52);

    if (len >= sizeof(buffer)) {
      return 2;
    }

    // Hash length
    memcpy(buffer, output + 64, len);

    // Do the "crypto" stuff
    CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash);
    CryptHashData(hash, (const BYTE*)output + 4, 0x28, 0);
    CryptDeriveKey(prov, CALG_3DES, hash, 0, &cryptKey);
    CryptDecrypt(cryptKey, 0, 1, 0, buffer, &len);

    // Output
    wprintf(L"%s\n", buffer);

    return 0;
}
