<?php declare(strict_types=1);

namespace C2DL\CC\Save_Crypto;

use C2DL\CC\Save_Crypto\AES_256_CBC_Service;
use C2DL\CC\Save_Crypto\model\Salt_Ciphertext_Wrapper;
use C2DL\CC\Save_Crypto\model\Key_IV_Wrapper;

class Save_Crypto_Service {

    const SAVE_PREFIX       = '[-!_0_!-]';
    const SALTED_PREFIX     = 'Salted__';

    const SAVE_PREFIX_LEN   = 9;
    const SALTED_PREFIX_LEN = 8;
    const SALT_LEN          = 8;
    const KEY_LEN           = 32;
    const IV_LEN            = 16;
    const DATA_LEN          = 48;

    public static function decrypt_save(
        string $savestring
        , string $pass
    ): string {
        $_salt_ciphertext = Save_Crypto_Service::binary_to_salt_ciphertext(
            base64_decode(
                Save_Crypto_Service::savestring_to_base64($savestring)
                , true
            )
        );
        $_key_iv = Save_Crypto_Service::salted_pass_to_key_iv(
            $pass
            , $_salt_ciphertext->getSalt()
        );
        return AES_256_CBC_Service::aes_decrypt(
            $_salt_ciphertext->getCiphertext()
            , $_key_iv->getIV()
            , $_key_iv->getKey()
        );
    }

    public static function encrypt_save(
        string $savedata
        , string $pass
    ): string {
        $_salt = random_bytes(Save_Crypto_Service::SALT_LEN);
        $_key_iv = Save_Crypto_Service::salted_pass_to_key_iv($pass, $_salt);
        $_ciphertext = AES_256_CBC_Service::aes_encrypt(
            $savedata
            , $_key_iv->getIV()
            , $_key_iv->getKey()
        );
        return Save_Crypto_Service::SAVE_PREFIX . base64_encode(
            Save_Crypto_Service::SALTED_PREFIX . $_salt . $_ciphertext
        );
    }

    // Helper
    // Base64

    public static function savestring_to_base64(string $savestring): string {
        $_savestring_prefix = substr(
            $savestring
            , 0
            , Save_Crypto_Service::SAVE_PREFIX_LEN
        );
        if (strcmp(
            Save_Crypto_Service::SAVE_PREFIX
            , $_savestring_prefix) == 0
        ) {
            return substr($savestring, Save_Crypto_Service::SAVE_PREFIX_LEN);
        }
        return $savestring;
    }

    // Salt

    public static function binary_to_salt_ciphertext(
        string $binary_data
    ): Salt_Ciphertext_Wrapper {
        if (strcmp(
            Save_Crypto_Service::SALTED_PREFIX
            , substr($binary_data, 0, Save_Crypto_Service::SALTED_PREFIX_LEN)
            ) != 0) {
            throw new \InvalidArgumentException('Data not salted', 100);
        }
        if (strlen($binary_data) <
            (Save_Crypto_Service::SALTED_PREFIX_LEN
                + Save_Crypto_Service::SALT_LEN)
        ) {
            throw new \LengthException('Salt has invalid length', 101);
        }

        $_salt = substr(
            $binary_data
            , Save_Crypto_Service::SALTED_PREFIX_LEN
            , Save_Crypto_Service::SALT_LEN);
        $_ciphertext = substr(
            $binary_data
            , Save_Crypto_Service::SALTED_PREFIX_LEN
                + Save_Crypto_Service::SALT_LEN
        );
        return new Salt_Ciphertext_Wrapper($_salt, $_ciphertext);
    }

    // Pass

    public static function salted_pass_to_key_iv(
        string $pass
        , string $salt
    ): Key_IV_Wrapper {
        if (strlen($salt) < Save_Crypto_Service::SALT_LEN) {
            throw new \LengthException('Salt has invalid length', 101);
        }

        $_pass_salt = $pass . $salt;
        $_round_key = md5($_pass_salt, true);
        $_accom_key_iv = $_round_key;
        while (strlen($_accom_key_iv) < Save_Crypto_Service::DATA_LEN) {
            $_round_key = md5($_round_key . $_pass_salt, true);
            $_accom_key_iv .= $_round_key;
        }
        $_key = substr($_accom_key_iv, 0, Save_Crypto_Service::KEY_LEN);
        $_iv = substr(
            $_accom_key_iv
            , Save_Crypto_Service::KEY_LEN
            , Save_Crypto_Service::IV_LEN
        );
        return new Key_IV_Wrapper($_key, $_iv);
    }

}
