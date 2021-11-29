<?php declare(strict_types=1);

namespace C2DL\CC\Save_Crypto\model;

class Salt_Ciphertext_Wrapper {

    public function __construct(
        private string $salt,
        private string $ciphertext,
    ) {}

    public function getSalt(): string {
        return $this->salt;
    }

    public function getCiphertext(): string {
        return $this->ciphertext;
    }

}
