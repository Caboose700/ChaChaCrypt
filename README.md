## ChaChaCrypt

A small command line utility to encrypt and decrypt files with XChaCha20-Poly1305 written in Go.

### Usage
```text
ccc_encrypt.exe "file.txt"
ccc_decrypt.exe "file.txt.ccc"

ccc_encrypt.exe -m 1024 "file.txt" "file2.txt" <...>
ccc_encrypt.exe -m 128 -t 8 -i 1 "file.txt"
```

### Command Line Arguments
```text
-m <1-65535> | Argon2id Memory Usage in MiB | Default: 64MiB  
-t <1-255>   | Argon2id Thread Count        | Default: 4
-i <1-255>   | Argon2id Iteration Count     | Default: 4
```

### Information
Files are encrypted in chunks, using the memory size specified for Argon2id to define the chunk size.

For example, if using the default Argon2id memory of 64MiB, each 64 MiB chunk of the file is encrypted with its own 
nonce.

This is done to keep memory usage of the program down, as for AEAD all bytes being encrypted need to be in memory. It's 
a safe assumption then that if the user uses 4GiB for key derivation, they have the RAM required to read and encrypt
4GiB chunks of data at a time.

### CCC File Format
Each CCC file contains a 24 byte header.

| Magic Number | Argon2id Memory Usage (in MiB) | Argon2id Thread Count | Argon2id Iteration Count | Argon2id Salt |
|--------------|--------------------------------|-----------------------|--------------------------|---------------|
| 4 Bytes      | 2 Bytes                        | 1 Byte                | 1 Byte                   | 16 Bytes      |

Each chunk has a 1 byte status flag, to indicate if it is the last chunk of the file. 

As the chunk size is derived from
Argon2id memory usage, the chunk's size isn't stored. If the chunk is the last chunk, the rest of the file is read.

|Status Byte|File Data|
|---|---|
|1 Byte|Variable Bytes|