Unreleased

    KeyWriter::to_hex, to_base64 and to_PEM return kmipcore::secure_string,
    which is now a class derived from std::basic_string instead of an
    alias; see the kmipclient CHANGELOG (Unreleased) for the source changes
    this can need.

Oct, 2026 Version 0.1.0

    Initial release. Key reading, writing and generation moved out of
    kmipclient into "kmiputil": KeyReader (aes_from_hex, aes_from_base64,
    aes_from_value, from_PEM), KeyWriter (to_hex, to_base64, to_PEM) and
    KeyGenerator (generate_aes).
    Unlike the kmipclient factory it replaces, aes_from_base64 rejects
    invalid Base64 (characters outside the alphabet, missing or misplaced
    padding, nonzero bits before the padding) instead of skipping it. An
    invalid AES key length throws with General Failure (0x100), like the
    other decoding errors, instead of -1. Unlike PEMReader, from_PEM stores
    private keys as PKCS#8 (the Key Format Type they are registered with) and
    sets the algorithm and length attributes on keys and certificates.
    from_PEM reads symmetric key material only between SYMMETRIC KEY
    BEGIN/END lines; PEMReader accepted any label, and a missing END line.
