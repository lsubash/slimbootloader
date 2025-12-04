#include <Library/ShellLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/BootloaderCommonLib.h>
#include <Library/LoaderPerformanceLib.h>
#include <Library/CryptoLib.h>

// Test vectors for AES-256-CBC
static UINT8 test_key_256[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

static UINT8 test_iv[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static UINT8 test_ciphertext[] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
    0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6
};

static UINT8 expected_plaintext[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};


/**
  Perform AES decryption test.

  @param[in]  Shell        shell instance
  @param[in]  Argc         number of command line arguments
  @param[in]  Argv         command line arguments

  @retval EFI_SUCCESS

**/
STATIC
EFI_STATUS
EFIAPI
ShellCommandDecryptFunc (
  IN SHELL  *Shell,
  IN UINTN   Argc,
  IN CHAR16 *Argv[]
  );

CONST SHELL_COMMAND ShellCommandDecrypt = {
  L"Decrypt",
  L"Perform decryption",
  &ShellCommandDecryptFunc
};

void test_aes_decrypt(void) {
    UINT8 plaintext[16];
    RETURN_STATUS status;
    
    status = AesDecrypt(
        test_ciphertext, 16,
        test_key_256, 32,
        test_iv,
        AES_MODE_CBC,
        plaintext, 16
    );
    
    ASSERT(status == RETURN_SUCCESS);
    ASSERT(CompareMem(plaintext, expected_plaintext, 16) == 0);
}


/**
 Test for AES-256-CBC decryption.

  @param[in]  Shell        shell instance
  @param[in]  Argc         number of command line arguments
  @param[in]  Argv         command line arguments

  @retval EFI_SUCCESS

**/
STATIC
EFI_STATUS
EFIAPI
ShellCommandDecryptFunc (
  IN SHELL  *Shell,
  IN UINTN   Argc,
  IN CHAR16 *Argv[]
  )
{
    ShellPrint (L" Running AES-256 Decrypt Tests...\n");
    
    test_aes_decrypt();
    
    ShellPrint (L" Tests passed \n");

    return EFI_SUCCESS;
}