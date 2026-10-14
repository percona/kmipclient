Oct, 2026 Version 0.4.0

    Key reading, writing and generation moved out of the Key classes into the
    new "kmiputil" library (KeyReader, KeyWriter, KeyGenerator).
    Removed: SymmetricKey::aes_from_hex/aes_from_base64/aes_from_value/
    generate_aes and PEMReader; see kmiputil/README.md for the replacements.
    New: writing keys as hex, Base64 and PEM.
    Fixed: keys read from PEM got Name = true instead of their name; reading
    an encrypted private key could prompt for a passphrase on the terminal.

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
