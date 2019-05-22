## Geth Private Key

Simple script to retrive the private key from a Geth keystore file.

To install:

```sh
% go install github.com/juztin/gethpkey
```

To use:

```sh
% gethpkey path/to/keystore.json
```
The decrypted private key will be saved to: `path/to/keystore.pkey`
