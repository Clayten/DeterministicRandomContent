# Deterministic Random Content

## About

Meant for storage testing. Uses AES to generate a wide range of bit patterns for more realistic testing, including of built-in filesystem compression.

Rather than requiring the tester to create a random file and then fingerprint it (with SHA256, etc) and store the fingerprints, or create a key per file and store the keys, DRC uses the pathname and the length as a key, ensuring each file is unique but not requiring any additional data to be generated and stored.

'testdir/dir1/file7 ; length 1024' -> Key Generation -> Content Generation

To check a file its name and length (as stored in the directory) are used to decrypt it. If the file is all zeros, it was not mangled during storage.

## Usage

```
load '~/dev/deterministic-random-content/drc.rb'
DeterministicRandomContent.write_file('kittens', 1024)
DeterministicRandomContent.verify_file('kittens')
```

From the terminal, truncate 'kittens' by a byte (or, add an extra byte)

```
DeterministicRandomContent.verify_file('kittens')
    RuntimeError: File kittens - verify error at bytes 0..4096
```

The algorithm detects which read block has the error but isn't more precise than that.

## License

AGPLv2
