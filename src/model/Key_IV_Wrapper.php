<?php declare(strict_types=1);

namespace C2DL\CC\Save_Crypto\model;

class Key_IV_Wrapper {

    public function __construct(
        private string $key,
        private string $iv,
    ) {}

    public function getKey(): string {
        return $this->key;
    }

    public function getIV(): string {
        return $this->iv;
    }

}
