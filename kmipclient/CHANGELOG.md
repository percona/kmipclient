Unreleased

    kmipcore changes the TTLV value types: TextString,
    ByteString and BigInteger hold their bytes in zeroed-on-free storage
    (kmipcore::secure_string and secure_bytes) instead of std::string and
    std::vector<uint8_t>. Code that reads or builds these members directly
    must change; Element::stringView() and Element::bytesView() return the
    value without a copy, toString() and toBytes() still return plain copies.
    Element::createByteString() and createBigInteger() take
    std::span<const uint8_t> or a braced list of bytes instead of
    const std::vector<uint8_t>&; calls with a vector still compile.
    kmipcore::secure_string is now a class derived from std::basic_string
    (it was an alias): its destructor, move operations and assignment from
    a plain string rvalue also zero the buffer inside the object that holds
    short values, which the allocator never sees. New:
    secure_string::wipe() and std::hash<secure_string>. Source changes: do
    not destroy or slice a secure_string through its base class; operator+
    and substr() return the plain base string; the inherited mutators
    (append(), operator+= ...) return a reference to the base class; there
    is no std::formatter for it (format std::string_view(s) instead).

Oct, 2026 Version 0.4.0

    Key reading, writing and generation moved out of the Key classes into the
    new "kmiputil" library (KeyReader, KeyWriter, KeyGenerator).
    Removed: SymmetricKey::aes_from_hex/aes_from_base64/aes_from_value/
    generate_aes and PEMReader; see kmiputil/README.md for the replacements.
    New: writing keys as hex, Base64 and PEM.
    Fixed: keys read from PEM got Name = true instead of their name; reading
    an encrypted private key could prompt for a passphrase on the terminal;
    a private key read from PEM was registered as PKCS#8 but held PKCS#1/SEC1
    bytes, with the DER encoding's size as its Cryptographic Length.
    Register sends Cryptographic Algorithm and Length only as a pair, as KMIP
    requires (1.4 §2.1.3): never the encoding's size as an asymmetric key's
    length, never a length without an algorithm, and no 2.0-only algorithm
    (e.g. Ed25519) over KMIP 1.x. Registering a symmetric key without a
    Cryptographic Algorithm (defined in the client's KMIP version) now throws
    instead of sending a Key Block KMIP does not allow.
    Requires kmipcore 0.3.0.
    op_get_key asks for private keys as PKCS#8 and public keys as X.509 when
    the server's default differs; it used to take any format as PKCS#8/X.509
    bytes, and threw for EC keys a server returned as a Transparent
    structure. A server that cannot convert keeps its own byte format.
    This costs up to two extra requests per asymmetric key fetched in
    another format (none for symmetric keys); see README.
    New: Key::key_format(), the Key Format Type of value(), which Register
    declares.
    Stricter: a key in a Get response whose Key Block has no Key Format Type
    (REQUIRED by KMIP 1.4 §2.1.3) is rejected; only symmetric keys were
    checked before.

Mar, 2026 Version 0.2.0

    Interface optimization
    Test suite update;
    Now it uses completely new low-level KMIP protocol implementation from "kmipcore" library,
    instead of old "libkmip" code.

Dec, 2025 Version 0.1.1

    Interface optimization 
    Test suite added
    Bugs fixed

Apr, 2025 Version 0.1.0

    Initial implementation of all functionality available in "kmippp"
