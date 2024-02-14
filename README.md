# crypto_enclave
Simple enclave implementing a cryptographic library

We write a wrapper around an [ED2556 RISC-V library](https://github.com/mit-enclaves/ed25519).
The wrapper makes it possible to keep the keys used by the library inside of the enclave and for the library functions to be accessed in a Remote Procedure Call style (RPC).
We add a queue to shared memory so untrusted applications can send requests to the library to generate keys (that will stay in enclave memory), or to sign messages using previously generated keys.
