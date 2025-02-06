# node-ntag424 [![CI](https://github.com/nikeee/node-ntag424/actions/workflows/CI.yaml/badge.svg)](https://github.com/nikeee/node-ntag424/actions/workflows/CI.yaml)

## Requirements

### You probably also need
- `@pokusew/pcsclite` for actually communicating with the tag (see examples).
  - On Linux, you may also need:
    - `apt install libpcsclite-dev pcsc-tools`
    - In case you have a ThinkPad with a built-in reader, it might conflict with libpcsclite. This may help: https://stackoverflow.com/a/66558992
    - This library was tested with the reader `Alcor Micro AU9540`
- You can use [`crypto.hkdf`](https://nodejs.org/api/crypto.html#cryptohkdfdigest-ikm-salt-info-keylen-callback) (builtin) or [`nistkdf-800-108`](https://github.com/nikeee/nistkdf-800-108) for key diversification/derivation.
- [`ndef`](https://github.com/don/ndef-js) to parse and create NDEF messages

## Usage
See `example` directory.
```sh
npm install ntag424
# keep in mind this project is AGPL licensed
```

## Development
```sh
npm ci
npm run compile
npm test # compile + tests
```

## Resources Used
### Data Sheets
- https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf
- https://www.nxp.com/docs/en/application-note/AN12196.pdf

### Blog Posts
- https://medium.com/@androidcrypto/demystify-the-secure-dynamic-message-with-ntag-424-dna-nfc-tags-android-java-part-1-b947c482913c
- https://medium.com/@androidcrypto/demystify-the-secure-dynamic-message-with-ntag-424-dna-nfc-tags-android-java-part-2-1f8878faa928

### Other Implementations
- https://github.com/AndroidCrypto/Ntag424SdmFeature
- https://github.com/johnnyb/ntag424-java
- https://gitlab.com/bettse/accessgranted
- https://github.com/MxAshUp/ntag424-js

Big thanks to all of you!

## License
See [LICENSE](./LICENSE). To contribute, you have to sign the [CLA](./CLA.md) in your first PR.
