/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_TEST_PEM_HPP
#define KMIPUTIL_TEST_PEM_HPP

#include <string_view>

// Fixtures generated with the openssl CLI: one P-256 key in PKCS#8 and
// traditional form, its public key, a self-signed certificate for it, and the
// same key encrypted with the passphrase "secret".
namespace kmiputil_test {

  inline constexpr std::string_view kEcPrivateKeyPkcs8 =
      R"PEM(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghLFYUa7Dh7il/ZWK
NPjLA56cbVE0ALKFabcTcg0rRWChRANCAAT0yfXClsjAl7hBcSNogGD+jsP31RB9
JuJ+4uC4CBlUeV6jgMZ6s7bRqLG4TanUAsLffbASzF/KnVC36QbY4AVF
-----END PRIVATE KEY-----
)PEM";

  inline constexpr std::string_view kEcPrivateKeyTraditional =
      R"PEM(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIISxWFGuw4e4pf2VijT4ywOenG1RNACyhWm3E3INK0VgoAoGCCqGSM49
AwEHoUQDQgAE9Mn1wpbIwJe4QXEjaIBg/o7D99UQfSbifuLguAgZVHleo4DGerO2
0aixuE2p1ALC332wEsxfyp1Qt+kG2OAFRQ==
-----END EC PRIVATE KEY-----
)PEM";

  inline constexpr std::string_view kEcPublicKey =
      R"PEM(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9Mn1wpbIwJe4QXEjaIBg/o7D99UQ
fSbifuLguAgZVHleo4DGerO20aixuE2p1ALC332wEsxfyp1Qt+kG2OAFRQ==
-----END PUBLIC KEY-----
)PEM";

  inline constexpr std::string_view kCertificate =
      R"PEM(-----BEGIN CERTIFICATE-----
MIIBiDCCAS2gAwIBAgIUVpQU1pyRPUA8/y3xr8SXfzbZCsowCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNa21pcHV0aWwtdGVzdDAgFw0yNjEwMTQxMDA1NDFaGA8yMTI2
MDkyMDEwMDU0MVowGDEWMBQGA1UEAwwNa21pcHV0aWwtdGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABPTJ9cKWyMCXuEFxI2iAYP6Ow/fVEH0m4n7i4LgIGVR5
XqOAxnqzttGosbhNqdQCwt99sBLMX8qdULfpBtjgBUWjUzBRMB0GA1UdDgQWBBTP
DV5PxQNchBKXw7Yw73gOKdOe2zAfBgNVHSMEGDAWgBTPDV5PxQNchBKXw7Yw73gO
KdOe2zAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQDJph8uq2gm
+in/PGXOinuoyUTd2itWI18XfClrcY5yxwIhAPLfhJBSXw1oFTGsj8s786cerEkj
XquWXblSpFGU5jd5
-----END CERTIFICATE-----
)PEM";

  inline constexpr std::string_view kEncryptedPrivateKey =
      R"PEM(-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBD1WO+geXmGV2oVkekC
nyPtAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQtq0t/JP75BUVPmmS
337u9ASBkNgLKzQ3WzeY1DP4ZHkICSX1a11J/uhFir9zCxDBwazQOo2QJf4yd0PB
Wt+Sp/doYxhwskwpzb80ogXRUUqMd6UYiTpnS7GExzJ1IeDS1OvJ+P0CvGu6Aj3Z
8G0bDGnkyy2K7Up5J08TbATGcPoNU4aFMVnpfRQA9QFewKA3tKbuadY/o0upLeBZ
Dnb/4cp54A==
-----END ENCRYPTED PRIVATE KEY-----
)PEM";

}  // namespace kmiputil_test

#endif  // KMIPUTIL_TEST_PEM_HPP
