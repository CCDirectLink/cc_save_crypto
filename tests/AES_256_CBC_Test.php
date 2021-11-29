<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use C2DL\CC\Save_Crypto\AES_256_CBC_Service;

final class AES_256_CBC_Test extends TestCase
{

    const IV_HEX         = '6449289f772a858fe3b20cbf9a7395a0';

    const CIPHERTEXT_HEX =
    'ae2e722a23846f923df5b2e86d53b6847421ded6b9114be6eaa6a1b3597b925e';
    const KEY_HEX        =
    'b90a91adcfadf88c11be9ed26199659b8593b3f4fae7a46995038aafcc0e6a34';

    const CONTENT        = '["example_savestring"]';

    /**
     * @covers C2DL\CC\Save_Crypto\AES_256_CBC_Service::aes_decrypt
     */
    public function test_aes_decrypt() {
        $_content = AES_256_CBC_Service::aes_decrypt(
            hex2bin(AES_256_CBC_Test::CIPHERTEXT_HEX)
            , hex2bin(AES_256_CBC_Test::IV_HEX)
            , hex2bin(AES_256_CBC_Test::KEY_HEX)
        );

        $this->assertSame(AES_256_CBC_Test::CONTENT, $_content);
    }

    /**
     * @covers C2DL\CC\Save_Crypto\AES_256_CBC_Service::aes_encrypt
     */
    public function test_aes_encrypt() {
        $_ciphertext = AES_256_CBC_Service::aes_encrypt(
            AES_256_CBC_Test::CONTENT
            , hex2bin(AES_256_CBC_Test::IV_HEX)
            , hex2bin(AES_256_CBC_Test::KEY_HEX)
        );

        $this->assertSame(
            AES_256_CBC_Test::CIPHERTEXT_HEX
            , bin2hex($_ciphertext)
        );
    }

}
