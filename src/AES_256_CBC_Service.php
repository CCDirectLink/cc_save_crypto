<?php declare(strict_types=1);

namespace C2DL\CC\Save_Crypto;

class AES_256_CBC_Service {

    const CIPHER    = "aes-256-cbc";

    const IV_LEN    = 16;
    const KEY_LEN   = 32;
    const BLOCK_LEN = 16;

    public static function aes_decrypt(
        string $message
        , string $iv
        , string $key
    ): string {
        $options = OPENSSL_RAW_DATA;
        $result = openssl_decrypt(
            $message
            , AES_256_CBC_Service::CIPHER
            , $key
            , $options
            , $iv
        );
        if ($result == false) {
            throw new \Exception(openssl_error_string());
        }
        return $result;
    }

    public static function aes_encrypt(
        string $message
        , string $iv
        , string $key
    ): string {
        $options = OPENSSL_RAW_DATA;
        $result = openssl_encrypt(
            $message
            , AES_256_CBC_Service::CIPHER
            , $key
            , $options
            , $iv
        );
        if ($result == false) {
            throw new \Exception(openssl_error_string());
        }
        return $result;
    }

}
