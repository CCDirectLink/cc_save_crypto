<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use C2DL\CC\Save_Crypto\Save_Crypto_Service;

final class Save_Crypto_Test extends TestCase
{

    // example data are encrypted via EXAMPLE_PASS
    // this pass is not valid for CC
    // the example savestring is not a valid CC Save

    const SAVE_PREFIX    = '[-!_0_!-]';
    const SAVE_BASE64    = 
    'U2FsdGVkX1/5tJNDdIY26a4uciojhG+SPfWy6G1TtoR0Id7WuRFL5uqmobNZe5Je';

    const EXAMPLE_PASS   = '123456';

    const SALT_HEX       = 'f9b49343748636e9';
    const IV_HEX         = '6449289f772a858fe3b20cbf9a7395a0';

    const CIPHERTEXT_HEX =
    'ae2e722a23846f923df5b2e86d53b6847421ded6b9114be6eaa6a1b3597b925e';
    const KEY_HEX        =
    'b90a91adcfadf88c11be9ed26199659b8593b3f4fae7a46995038aafcc0e6a34';

    const SAVE_CONTENT   = '["example_savestring"]';

    /**
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::savestring_to_base64
     */
    public function test_savestring_to_base64() {
        $_base64_1 = Save_Crypto_Service::savestring_to_base64(
            Save_Crypto_Test::SAVE_BASE64
        );
        $_base64_2 = Save_Crypto_Service::savestring_to_base64(
            Save_Crypto_Test::SAVE_PREFIX . Save_Crypto_Test::SAVE_BASE64
        );

        $this->assertSame($_base64_1, Save_Crypto_Test::SAVE_BASE64);
        $this->assertSame($_base64_2, Save_Crypto_Test::SAVE_BASE64);
    }
    
    /**
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::binary_to_salt_ciphertext
     * @covers C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper::__construct
     * @covers C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper::getCiphertext
     * @covers C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper::getSalt
     */
    public function test_binary_to_salt_ciphertext() {
        
        try {
            Save_Crypto_Service::binary_to_salt_ciphertext(
                hex2bin(Save_Crypto_Test::CIPHERTEXT_HEX)
            );
            $this->fail('Error required: Unsalted binary conversion');
        }
        catch(\InvalidArgumentException $e) {
            $this->assertSame($e->getMessage(), 'Data not salted');
            $this->assertSame($e->getCode(), 100);
        }
        catch(\Exception $e) {
            $this->fail('Unexpected exception: ' . $e->getMessage());
        }

        try {
            Save_Crypto_Service::binary_to_salt_ciphertext(
                substr(base64_decode(Save_Crypto_Test::SAVE_BASE64), 0, 12)
            );
            $this->fail('Error required: Salt missing');
        }
        catch(\LengthException $e) {
            $this->assertSame($e->getMessage(), 'Salt has invalid length');
            $this->assertSame($e->getCode(), 101);
        }
        catch(\Exception $e) {
            $this->fail('Unexpected exception: ' . $e->getMessage());
        }

        $_salt_ciphertext = Save_Crypto_Service::binary_to_salt_ciphertext(
            base64_decode(Save_Crypto_Test::SAVE_BASE64)
        );

        $this->assertSame(
            Save_Crypto_Test::SALT_HEX
            , bin2hex($_salt_ciphertext->getSalt())
        );
        $this->assertSame(
            Save_Crypto_Test::CIPHERTEXT_HEX
            , bin2hex($_salt_ciphertext->getCiphertext())
        );
    }

    /**
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::salted_pass_to_key_iv
     * @covers C2DL\CC\Save_Crypto\model\Key_IV_Wrapper::__construct
     * @covers C2DL\CC\Save_Crypto\model\Key_IV_Wrapper::getKey
     * @covers C2DL\CC\Save_Crypto\model\Key_IV_Wrapper::getIV
     */
    public function test_salted_pass_to_key_iv() {
        $_key_iv = Save_Crypto_Service::salted_pass_to_key_iv(
            Save_Crypto_Test::EXAMPLE_PASS
            , hex2bin(Save_Crypto_Test::SALT_HEX)
        );
        $this->assertSame(
            Save_Crypto_Test::KEY_HEX
            , bin2hex($_key_iv->getKey())
        );
        $this->assertSame(
            Save_Crypto_Test::IV_HEX
            , bin2hex($_key_iv->getIV())
        );
    }

    // integration tests

    /**
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::decrypt_save
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::savestring_to_base64
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::salted_pass_to_key_iv
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::binary_to_salt_ciphertext
     * @covers C2DL\CC\Save_Crypto\AES_256_CBC_Service::aes_decrypt
     * @covers C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper::__construct
     * @covers C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper::getCiphertext
     * @covers C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper::getSalt
     * @covers C2DL\CC\Save_Crypto\model\Key_IV_Wrapper::__construct
     * @covers C2DL\CC\Save_Crypto\model\Key_IV_Wrapper::getKey
     * @covers C2DL\CC\Save_Crypto\model\Key_IV_Wrapper::getIV
     */
    public function test_decrypt_save() {
        $_save_data = Save_Crypto_Service::decrypt_save(
            Save_Crypto_Test::SAVE_PREFIX . Save_Crypto_Test::SAVE_BASE64
            , Save_Crypto_Test::EXAMPLE_PASS
        );

        $this->assertSame(Save_Crypto_Test::SAVE_CONTENT, $_save_data);
    }

     /**
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::encrypt_save
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::decrypt_save
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::savestring_to_base64
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::salted_pass_to_key_iv
     * @covers C2DL\CC\Save_Crypto\Save_Crypto_Service::binary_to_salt_ciphertext
     * @covers C2DL\CC\Save_Crypto\AES_256_CBC_Service::aes_encrypt
     * @covers C2DL\CC\Save_Crypto\AES_256_CBC_Service::aes_decrypt
     * @covers C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper::__construct
     * @covers C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper::getCiphertext
     * @covers C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper::getSalt
     * @covers C2DL\CC\Save_Crypto\model\Key_IV_Wrapper::__construct
     * @covers C2DL\CC\Save_Crypto\model\Key_IV_Wrapper::getKey
     * @covers C2DL\CC\Save_Crypto\model\Key_IV_Wrapper::getIV
     */
    public function test_encrypt_decrypt_save() {
        $_save_enc = Save_Crypto_Service::encrypt_save(
            Save_Crypto_Test::SAVE_CONTENT
            , Save_Crypto_Test::EXAMPLE_PASS
        );
        $_save_data = Save_Crypto_Service::decrypt_save(
            $_save_enc
            , Save_Crypto_Test::EXAMPLE_PASS
        );

        $this->assertSame(Save_Crypto_Test::SAVE_CONTENT, $_save_data);
    }

}