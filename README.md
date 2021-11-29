# CrossCode Save Crypto-Library (PHP)

A PHP based library to de- and encrypt CrossCode savestrings.

## Requirements

- PHP: `^8.0`
- OpenSSL

## Decrypt

```
use C2DL\CC\Save_Crypto\Save_Crypto_Service;

// [...]

$save = Save_Crypto_Service::decrypt_save($savestring, $pass);
```

- `$savestring` contains the encrypted savestring with or without `[-!_0_!-]`.
- `$pass` contains the passprase that is used to encrypt CrossCode-saves.
- Returns the decrypted Save

## Encrypt

```
use C2DL\CC\Save_Crypto\Save_Crypto_Service;

// [...]

$save = Save_Crypto_Service::encrypt_save($savedata, $pass);
```

- `$savedata` contains the json based save-data that should be encrypted.
- `$pass` contains the passprase that is used to encrypt CrossCode-saves.
- Returns the encrypted Save
