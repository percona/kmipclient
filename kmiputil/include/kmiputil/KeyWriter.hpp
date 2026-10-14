/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_KEY_WRITER_HPP
#define KMIPUTIL_KEY_WRITER_HPP

#include "kmipclient/KeyBase.hpp"
#include "kmipcore/secure_memory.hpp"

namespace kmiputil {

  /**
   * Serializes client key objects to external representations (hex, Base64,
   * PEM). The results hold key material, so they are returned in
   * @ref kmipcore::secure_string, which is zeroed when freed.
   */
  class KeyWriter {
  public:
    KeyWriter() = delete;

    /** @brief Returns the key material as lowercase hex. */
    [[nodiscard]] static kmipcore::secure_string
        to_hex(const kmipclient::Key &key);

    /** @brief Returns the key material as padded Base64, without line breaks.
     */
    [[nodiscard]] static kmipcore::secure_string
        to_base64(const kmipclient::Key &key);

    /**
     * @brief Returns the key as PEM text that @ref KeyReader::from_PEM reads
     * back into the same key type.
     *
     * - X.509 certificate: `CERTIFICATE`
     * - private key: unencrypted PKCS#8 `PRIVATE KEY`
     * - public key: `PUBLIC KEY` (SubjectPublicKeyInfo)
     * - symmetric key: the Base64 key material between
     *   `SYMMETRIC KEY` BEGIN/END lines (no standard PEM type exists)
     *
     * @throws kmipcore::KmipException if the key material cannot be parsed
     * for its type.
     */
    [[nodiscard]] static kmipcore::secure_string
        to_PEM(const kmipclient::Key &key);
  };

}  // namespace kmiputil

#endif  // KMIPUTIL_KEY_WRITER_HPP
