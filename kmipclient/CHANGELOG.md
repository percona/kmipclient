Unreleased

    timeout_ms bounds each request/response exchange as a whole, not each
    socket read: an exchange fails with KmipIOException ("timed out") when it
    has not completed timeout_ms after it started. So timeout_ms must cover
    the largest expected response; the NetClientOpenSSL default stays 500 ms.
    Reconnecting after a failed exchange has its own timeout_ms.
    New: NetClient::set_io_deadline() (virtual), io_deadline() and
    timeout_ms(). NetClient::is_connected() is now virtual. A custom
    NetClient should not block past io_deadline() in send() and recv(), and
    its connect() and close() must keep m_isConnected up to date: the client
    now calls connect() before an exchange when is_connected() is false. One
    that wraps another NetClient should override set_io_deadline() to call
    the base version and forward the deadline, and is_connected() to return
    the wrapped client's state.
    NetClientOpenSSL::send() and recv() clear the thread's OpenSSL error
    queue.
    NetClient has a new data member and new virtual functions, so code built
    against an earlier version must be rebuilt.

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
