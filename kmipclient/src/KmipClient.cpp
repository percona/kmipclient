/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/KmipClient.hpp"

#include "IOUtils.hpp"
#include "kmipcore/attributes_parser.hpp"
#include "kmipcore/key_parser.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/kmip_requests.hpp"
#include "kmipcore/response_parser.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <unordered_set>

namespace kmipclient {

  static std::vector<std::string> default_get_key_attrs(bool all_attributes) {
    if (all_attributes) {
      return {};
    }
    return {
        KMIP_ATTR_NAME_STATE,
        KMIP_ATTR_NAME_NAME,
        KMIP_ATTR_NAME_OPERATION_POLICY_NAME,
        KMIP_ATTR_NAME_CRYPTO_ALG,
        KMIP_ATTR_NAME_CRYPTO_LEN,
        KMIP_ATTR_NAME_CRYPTO_USAGE_MASK
    };
  }

  static std::vector<std::string>
      default_get_secret_attrs(bool all_attributes) {
    if (all_attributes) {
      return {};
    }
    return {
        KMIP_ATTR_NAME_STATE,
        KMIP_ATTR_NAME_NAME,
        KMIP_ATTR_NAME_OPERATION_POLICY_NAME
    };
  }

  // The Key Format Types op_get_key asks for an asymmetric key in, in order:
  // the ones Register declares by default and kmiputil::KeyReader produces,
  // so a fetched key reads the same as a registered one. Without asking,
  // servers return their own default, e.g. PKCS#1 for RSA, or a Transparent
  // structure for EC, which has no byte encoding. A server need only return
  // a key in the format it was registered in; other conversions are
  // optional (KMIP 1.4 §4.11, 2.0 §6.1.19). Symmetric keys are Raw already.
  static std::vector<int32_t> preferred_key_formats(int32_t object_type) {
    switch (object_type) {
      case kmipcore::KMIP_OBJTYPE_PRIVATE_KEY:
        return {kmipcore::KMIP_KEYFORMAT_PKCS8};
      case kmipcore::KMIP_OBJTYPE_PUBLIC_KEY:
        // KMIP encodes a public key's SubjectPublicKeyInfo as X.509 and
        // defines PKCS#8 for private keys only (1.4 §2.1.3, 2.0 §11.25).
        // Cosmian KMS deviates: it exports SubjectPublicKeyInfo only under
        // the PKCS#8 label, so that is tried second.
        return {kmipcore::KMIP_KEYFORMAT_X509, kmipcore::KMIP_KEYFORMAT_PKCS8};
      default:
        return {};
    }
  }

  // Marks the thread's OpenSSL error queue for a later ERR_pop_to_mark(),
  // with a placeholder error above the mark. OpenSSL 1.1.1 marks an entry
  // with a flag, not a count, so a mark OpenSSL sets and pops itself on the
  // same top entry (d2i_X509_PUBKEY does) would clear ours, and our pop
  // would then drop the caller's errors too. kmiputil's OpenSslErrorScope
  // does the same.
  static void mark_openssl_errors() {
    ERR_set_mark();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
    ERR_raise(ERR_LIB_USER, 0xA5A);
#else
    ERR_put_error(ERR_LIB_USER, 0, 0xA5A, __FILE__, __LINE__);
#endif
  }

  // Whether `der` is exactly one DER SubjectPublicKeyInfo. Checks the ASN.1
  // structure only, so it holds for key types OpenSSL cannot decode too.
  static bool is_subject_public_key_info(std::span<const unsigned char> der) {
    if (der.empty() || der.size() > static_cast<std::size_t>(LONG_MAX)) {
      return false;
    }
    // A failed parse pushes OpenSSL errors; keep them out of later calls
    // (e.g. TLS) without dropping any the caller had pending.
    mark_openssl_errors();
    const unsigned char *p = der.data();
    X509_PUBKEY *spki =
        d2i_X509_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
    const bool whole = spki && p == der.data() + der.size();
    X509_PUBKEY_free(spki);
    ERR_pop_to_mark();
    return whole;
  }

  // `key`, which came back in one of preferred_key_formats(), if op_get_key
  // can return it as such, or null to treat it as not converted. A public
  // key under the PKCS#8 label (Cosmian KMS, see above) qualifies only if it
  // holds a SubjectPublicKeyInfo, which KMIP calls X.509: it is recorded as
  // such, so registering the key again declares the standard format.
  // Anything else under that label is no public key format KMIP defines.
  static std::unique_ptr<Key> in_preferred_format(std::unique_ptr<Key> key) {
    if (key->type() == KeyType::PUBLIC_KEY &&
        key->key_format() ==
            static_cast<int32_t>(kmipcore::KMIP_KEYFORMAT_PKCS8)) {
      if (!is_subject_public_key_info(key->value())) {
        return nullptr;
      }
      key->set_key_format(kmipcore::KMIP_KEYFORMAT_X509);
    }
    return key;
  }

  static bool should_retry_get_attributes_with_legacy_v2_encoding(
      const kmipcore::KmipException &e
  ) {
    switch (e.code().value()) {
      case kmipcore::KMIP_REASON_INVALID_MESSAGE:
      case kmipcore::KMIP_REASON_INVALID_FIELD:
      case kmipcore::KMIP_REASON_FEATURE_NOT_SUPPORTED:
        return true;
      default:
        return false;
    }
  }

  KmipClient::KmipClient(
      NetClient &net_client,
      const std::shared_ptr<kmipcore::Logger> &logger,
      kmipcore::ProtocolVersion version,
      bool close_on_destroy
  )
    : net_client(&net_client),
      io(std::make_unique<IOUtils>(net_client, logger)),
      version_(version),
      close_on_destroy_(close_on_destroy) {}

  KmipClient::KmipClient(
      std::shared_ptr<NetClient> net_client,
      const std::shared_ptr<kmipcore::Logger> &logger,
      kmipcore::ProtocolVersion version,
      bool close_on_destroy
  )
    : net_client(net_client.get()),
      net_client_owner_(std::move(net_client)),
      io(),
      version_(version),
      close_on_destroy_(close_on_destroy) {
    if (this->net_client == nullptr) {
      throw std::invalid_argument("KmipClient: net_client must not be null");
    }
    io = std::make_unique<IOUtils>(*this->net_client, logger);
  }

  KmipClient::KmipClient(KmipClient &&other) noexcept
    : net_client(other.net_client),
      net_client_owner_(std::move(other.net_client_owner_)),
      io(std::move(other.io)),
      version_(other.version_),
      close_on_destroy_(other.close_on_destroy_) {
    other.net_client = nullptr;
    other.close_on_destroy_ = false;
  }

  KmipClient &KmipClient::operator=(KmipClient &&other) noexcept {
    if (this != &other) {
      net_client = other.net_client;
      net_client_owner_ = std::move(other.net_client_owner_);
      io = std::move(other.io);
      version_ = other.version_;
      close_on_destroy_ = other.close_on_destroy_;

      other.net_client = nullptr;
      other.close_on_destroy_ = false;
    }
    return *this;
  }

  std::shared_ptr<KmipClient> KmipClient::create_shared(
      NetClient &net_client,
      const std::shared_ptr<kmipcore::Logger> &logger,
      kmipcore::ProtocolVersion version,
      bool close_on_destroy
  ) {
    return std::make_shared<KmipClient>(
        net_client, logger, version, close_on_destroy
    );
  }

  std::shared_ptr<KmipClient> KmipClient::create_shared(
      std::shared_ptr<NetClient> net_client,
      const std::shared_ptr<kmipcore::Logger> &logger,
      kmipcore::ProtocolVersion version,
      bool close_on_destroy
  ) {
    return std::make_shared<KmipClient>(
        std::move(net_client), logger, version, close_on_destroy
    );
  }

  KmipClient::~KmipClient() {
    // Reference-based construction is non-owning by default; close only when
    // explicitly requested (or when using an owning/shared setup).
    if (close_on_destroy_ && net_client != nullptr) {
      net_client->close();
    }
  }

  std::string KmipClient::op_register_key(
      const std::string &name, const std::string &group, const Key &k
  ) const {
    auto request = make_request_message();
    const auto batch_item_id = request.add_batch_item(
        kmipcore::RegisterKeyRequest(
            name,
            group,
            k.to_core_key(),
            request.getHeader().getProtocolVersion()
        )
    );

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::RegisterResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  std::string KmipClient::op_register_secret(
      const std::string &name, const std::string &group, const Secret &secret
  ) const {
    auto request = make_request_message();
    const auto batch_item_id = request.add_batch_item(
        kmipcore::RegisterSecretRequest(
            name,
            group,
            secret.value(),
            secret.get_secret_type(),
            request.getHeader().getProtocolVersion()
        )
    );

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::RegisterResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  std::string KmipClient::op_create_aes_key(
      const std::string &name,
      const std::string &group,
      aes_key_size key_size,
      cryptographic_usage_mask usage_mask
  ) const {
    auto request = make_request_message();
    const auto batch_item_id = request.add_batch_item(
        kmipcore::CreateSymmetricKeyRequest(
            name,
            group,
            static_cast<int32_t>(key_size),
            usage_mask,
            request.getHeader().getProtocolVersion()
        )
    );

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::CreateResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  std::unique_ptr<Key>
      KmipClient::op_get_key(const std::string &id, bool all_attributes) const {
    const auto requested_attrs = default_get_key_attrs(all_attributes);
    const auto execute = [&](bool legacy_attribute_names_for_v2) {
      auto request = make_request_message();
      const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));

      const auto attributes_item_id = request.add_batch_item(
          kmipcore::GetAttributesRequest(
              id,
              requested_attrs,
              request.getHeader().getProtocolVersion(),
              legacy_attribute_names_for_v2
          )
      );

      kmipcore::secure_bytes response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );

      kmipcore::ResponseParser rf(response_bytes, request);
      const auto get_response =
          rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
              get_item_id
          );

      auto attrs_response =
          rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
              attributes_item_id
          );
      kmipcore::Attributes server_attrs =
          kmipcore::AttributesParser::parse(attrs_response.getAttributes());

      // Verify required attributes are present in the server response.
      if (!server_attrs.has_attribute(KMIP_ATTR_NAME_STATE)) {
        throw kmipcore::KmipException(
            "Required attribute 'State' missing from server response"
        );
      }
      // Only now, with Get Attributes settled, may key_from_get_response
      // ask for the key again: the retries below are for Get Attributes
      // errors and must neither see nor repeat its requests.
      auto key = key_from_get_response(id, get_response);
      // Merge server-provided metadata (state, name, dates, …) into the key.
      key->attributes().merge(server_attrs);
      return key;
    };

    try {
      return execute(false);
    } catch (const kmipcore::KmipException &first_error) {
      if (!version_.is_at_least(2, 0) ||
          !should_retry_get_attributes_with_legacy_v2_encoding(first_error)) {
        throw;
      }
    }
    try {
      return execute(true);
    } catch (const kmipcore::KmipException &second_error) {
      if (requested_attrs.empty() ||
          !should_retry_get_attributes_with_legacy_v2_encoding(second_error)) {
        throw;
      }
    }

    // Compatibility fallback for servers that reject explicit selectors in
    // Get Attributes requests: request all attributes and filter client-side.
    auto request = make_request_message();
    const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));
    const auto attributes_item_id = request.add_batch_item(
        kmipcore::GetAttributesRequest(
            id, {}, request.getHeader().getProtocolVersion(), true
        )
    );
    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );
    kmipcore::ResponseParser rf(response_bytes, request);
    const auto get_response =
        rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
            get_item_id
        );
    auto attrs_response =
        rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
            attributes_item_id
        );
    kmipcore::Attributes server_attrs =
        kmipcore::AttributesParser::parse(attrs_response.getAttributes());
    if (!server_attrs.has_attribute(KMIP_ATTR_NAME_STATE)) {
      throw kmipcore::KmipException(
          "Required attribute 'State' missing from server response"
      );
    }
    auto key = key_from_get_response(id, get_response);
    key->attributes().merge(server_attrs);
    return key;
  }

  std::unique_ptr<Key> KmipClient::key_from_get_response(
      const std::string &id, const kmipcore::GetResponseBatchItem &response
  ) const {
    const auto parse = [](const kmipcore::GetResponseBatchItem &r) {
      return Key::from_core_key(kmipcore::KeyParser::parseGetKeyResponse(r));
    };
    const auto formats = preferred_key_formats(response.getObjectType());
    if (formats.empty()) {
      return parse(response);
    }
    const auto got = kmipcore::KeyParser::keyFormatType(response);
    if (got && std::ranges::find(formats, *got) != formats.end()) {
      if (auto key = in_preferred_format(parse(response))) {
        return key;
      }
    }

    // Ask for each preferred format in turn. The plain Get just succeeded,
    // so a failed one here is about the format, whatever reason the server
    // gives: KMIP defines Key Format Type Not Supported (1.4 §6.10), Cosmian
    // KMS answers Operation Not Supported, others may differ. So any server
    // failure moves on rather than fail where the plain Get worked; only
    // I/O and parse errors are thrown.
    for (const int32_t format : formats) {
      auto request = make_request_message();
      const auto get_item_id =
          request.add_batch_item(kmipcore::GetRequest(id, format));
      kmipcore::secure_bytes response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );
      kmipcore::ResponseParser rf(response_bytes, request);
      if (rf.getOperationResultByBatchItemId(get_item_id).resultStatus !=
          kmipcore::KMIP_STATUS_SUCCESS) {
        continue;
      }
      const auto refetched =
          rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
              get_item_id
          );
      if (kmipcore::KeyParser::keyFormatType(refetched) == format) {
        if (auto key = in_preferred_format(parse(refetched))) {
          return key;
        }
      }
      // Answered in some other format, or under the PKCS#8 label with no
      // SubjectPublicKeyInfo: as good as a refusal.
    }

    // No conversion: keep the server's own format, which key_format()
    // records. This throws for a Transparent format, which has no bytes.
    return parse(response);
  }

  Secret KmipClient::op_get_secret(
      const std::string &id, bool all_attributes
  ) const {
    const auto requested_attrs = default_get_secret_attrs(all_attributes);
    const auto execute = [&](bool legacy_attribute_names_for_v2) {
      auto request = make_request_message();
      const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));

      const auto attributes_item_id = request.add_batch_item(
          kmipcore::GetAttributesRequest(
              id,
              requested_attrs,
              request.getHeader().getProtocolVersion(),
              legacy_attribute_names_for_v2
          )
      );

      kmipcore::secure_bytes response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );

      kmipcore::ResponseParser rf(response_bytes, request);
      auto get_response =
          rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
              get_item_id
          );
      Secret secret = kmipcore::KeyParser::parseGetSecretResponse(get_response);

      auto attrs_response =
          rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
              attributes_item_id
          );
      kmipcore::Attributes server_attrs =
          kmipcore::AttributesParser::parse(attrs_response.getAttributes());

      if (all_attributes) {
        // Merge all server-provided attributes into the secret.
        secret.attributes().merge(server_attrs);
      } else {
        if (!server_attrs.has_attribute(KMIP_ATTR_NAME_STATE)) {
          throw kmipcore::KmipException(
              "Required attribute 'State' missing from server response"
          );
        }
        // Copy only the minimal set: state (typed) + optional name (generic).
        secret.set_state(server_attrs.object_state());
        if (server_attrs.has_attribute(KMIP_ATTR_NAME_NAME)) {
          secret.set_attribute(
              KMIP_ATTR_NAME_NAME,
              std::string(server_attrs.get(KMIP_ATTR_NAME_NAME))
          );
        }
      }

      return secret;
    };

    try {
      return execute(false);
    } catch (const kmipcore::KmipException &first_error) {
      if (!version_.is_at_least(2, 0) ||
          !should_retry_get_attributes_with_legacy_v2_encoding(first_error)) {
        throw;
      }
    }
    try {
      return execute(true);
    } catch (const kmipcore::KmipException &second_error) {
      if (requested_attrs.empty() ||
          !should_retry_get_attributes_with_legacy_v2_encoding(second_error)) {
        throw;
      }
    }

    auto request = make_request_message();
    const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));
    const auto attributes_item_id = request.add_batch_item(
        kmipcore::GetAttributesRequest(
            id, {}, request.getHeader().getProtocolVersion(), true
        )
    );
    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );
    kmipcore::ResponseParser rf(response_bytes, request);
    auto get_response =
        rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
            get_item_id
        );
    Secret secret = kmipcore::KeyParser::parseGetSecretResponse(get_response);
    auto attrs_response =
        rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
            attributes_item_id
        );
    kmipcore::Attributes server_attrs =
        kmipcore::AttributesParser::parse(attrs_response.getAttributes());
    if (all_attributes) {
      secret.attributes().merge(server_attrs);
    } else {
      if (!server_attrs.has_attribute(KMIP_ATTR_NAME_STATE)) {
        throw kmipcore::KmipException(
            "Required attribute 'State' missing from server response"
        );
      }
      secret.set_state(server_attrs.object_state());
      if (server_attrs.has_attribute(KMIP_ATTR_NAME_NAME)) {
        secret.set_attribute(
            KMIP_ATTR_NAME_NAME,
            std::string(server_attrs.get(KMIP_ATTR_NAME_NAME))
        );
      }
    }
    return secret;
  }

  std::string KmipClient::op_activate(const std::string &id) const {
    auto request = make_request_message();
    const auto batch_item_id =
        request.add_batch_item(kmipcore::ActivateRequest(id));

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::ActivateResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  std::vector<std::string>
      KmipClient::op_get_attribute_list(const std::string &id) const {
    auto request = make_request_message();
    const auto batch_item_id =
        request.add_batch_item(kmipcore::GetAttributeListRequest(id));

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    auto response = rf.getResponseByBatchItemId<
        kmipcore::GetAttributeListResponseBatchItem>(batch_item_id);
    return std::vector<std::string>{
        response.getAttributeNames().begin(), response.getAttributeNames().end()
    };
  }

  kmipcore::Attributes KmipClient::op_get_attributes(
      const std::string &id, const std::vector<std::string> &attr_names
  ) const {
    const auto execute = [&](const std::vector<std::string> &selectors,
                             bool legacy_attribute_names_for_v2) {
      auto request = make_request_message();
      const auto batch_item_id = request.add_batch_item(
          kmipcore::GetAttributesRequest(
              id,
              selectors,
              request.getHeader().getProtocolVersion(),
              legacy_attribute_names_for_v2
          )
      );

      kmipcore::secure_bytes response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );

      kmipcore::ResponseParser rf(response_bytes, request);
      auto response =
          rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
              batch_item_id
          );
      return kmipcore::AttributesParser::parse(response.getAttributes());
    };

    try {
      return execute(attr_names, false);
    } catch (const kmipcore::KmipException &first_error) {
      if (!version_.is_at_least(2, 0) ||
          !should_retry_get_attributes_with_legacy_v2_encoding(first_error)) {
        throw;
      }
    }
    try {
      return execute(attr_names, true);
    } catch (const kmipcore::KmipException &second_error) {
      if (attr_names.empty() ||
          !should_retry_get_attributes_with_legacy_v2_encoding(second_error)) {
        throw;
      }
    }
    return execute({}, true);
  }

  std::vector<std::string> KmipClient::op_locate_by_name(
      const std::string &name, object_type o_type
  ) const {
    return locate_all(
               false, name, o_type, MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH
    )
        .ids;
  }

  // Response-size allowance per requested id: what a regular page of
  // MAX_ITEMS_IN_BATCH ids gets from the default limit (4 KiB per id).
  constexpr std::size_t LOCATE_RESPONSE_BYTES_PER_ID =
      kmipcore::RequestMessage::DEFAULT_MAX_RESPONSE_SIZE / MAX_ITEMS_IN_BATCH;

  // Response-size limit for a Locate of `page_size` ids. It grows with the
  // page, giving larger fallback pages the same allowance per id as a
  // regular page, but never drops below the usual default and never exceeds
  // the receive path's absolute KMIP_MAX_MESSAGE_HARD_LIMIT, so a server
  // cannot make the client buffer more than that whatever it sends.
  static std::size_t locate_response_size_limit(std::size_t page_size) {
    if (page_size >
        kmipcore::KMIP_MAX_MESSAGE_HARD_LIMIT / LOCATE_RESPONSE_BYTES_PER_ID) {
      return kmipcore::KMIP_MAX_MESSAGE_HARD_LIMIT;
    }
    return std::max(
        page_size * LOCATE_RESPONSE_BYTES_PER_ID,
        kmipcore::RequestMessage::DEFAULT_MAX_RESPONSE_SIZE
    );
  }

  // Located Items as a total for the whole search, or nullopt when it can't
  // be one. KMIP defines it as the count of all matching objects, but Cosmian
  // KMS over KMIP 2.0 reports how many identifiers that response holds. A
  // value no larger than the page it came with says nothing about objects
  // beyond that page, so it is not used to decide the search is complete.
  static std::optional<std::size_t> located_total(
      const std::optional<std::size_t> &located_items, std::size_t page_count
  ) {
    if (located_items.has_value() && *located_items > page_count) {
      return located_items;
    }
    return std::nullopt;
  }

  // Appends each id from `page` that is not already in `seen` to `result`,
  // up to `max_ids` entries total. Returns whether anything new was added.
  // Bounding by max_ids keeps memory use capped regardless of how many
  // (possibly duplicate, possibly adversarial) ids a server reports.
  static bool merge_new_ids(
      std::vector<std::string> &result,
      std::unordered_set<std::string> &seen,
      const std::vector<std::string> &page,
      std::size_t max_ids
  ) {
    bool added_any = false;
    for (const auto &id : page) {
      if (result.size() >= max_ids) {
        break;
      }
      if (seen.insert(id).second) {
        result.push_back(id);
        added_any = true;
      }
    }
    return added_any;
  }

  // Whether two pages hold the same set of ids.
  static bool same_ids(
      const std::vector<std::string> &a, const std::vector<std::string> &b
  ) {
    return std::unordered_set<std::string>(a.begin(), a.end()) ==
           std::unordered_set<std::string>(b.begin(), b.end());
  }

  KmipClient::LocateOutcome KmipClient::locate_all(
      bool by_group,
      const std::string &filter,
      object_type o_type,
      std::size_t max_ids
  ) const {
    LocateOutcome outcome;
    if (max_ids == 0) {
      outcome.confirmed_complete = true;
      return outcome;
    }

    auto &result = outcome.ids;
    auto &seen = outcome.seen;
    std::size_t offset = 0;
    std::optional<std::size_t> known_total;
    bool finished = false;
    bool stalled = false;

    for (std::size_t batch = 0;
         batch < MAX_BATCHES_IN_SEARCH && result.size() < max_ids;
         ++batch) {
      const std::size_t page_size =
          std::min(max_ids - result.size(), MAX_ITEMS_IN_BATCH);
      std::optional<std::size_t> located_items;
      const auto got = locate_page(
          by_group,
          filter,
          o_type,
          offset,
          page_size,
          &located_items,
          kmipcore::RequestMessage::DEFAULT_MAX_RESPONSE_SIZE
      );

      if (got.empty()) {
        // The end of the list, unless a usable total says ids are missing.
        stalled = known_total.has_value() && result.size() < *known_total;
        finished = !stalled;
        break;
      }

      const std::size_t known_before = result.size();
      merge_new_ids(result, seen, got, max_ids);
      const bool first_page = offset == 0;
      offset += got.size();
      if (const auto total = located_total(located_items, got.size())) {
        known_total = total;
      }

      if (known_total.has_value() && result.size() >= *known_total) {
        outcome.confirmed_complete = true;
        finished = true;
        break;
      }
      if (result.size() >= max_ids) {
        finished = true;
        break;
      }
      if (result.size() - known_before < got.size()) {
        // The page repeats ids already seen although the offset moved on.
        // Either the server ignores Offset Items (observed: Cosmian KMS,
        // which returns the first page for every offset), or its order
        // changed between requests, in which case some ids may have been
        // skipped. Paging cannot tell which, so switch to the single-page
        // fallback below, which handles both.
        stalled = true;
        break;
      }
      if (known_total.has_value() && offset >= *known_total) {
        // The server's own count says ids are still missing.
        stalled = true;
        break;
      }
      if (got.size() < page_size && !known_total.has_value()) {
        // KMIP lets a server cap a page only when Maximum Items is omitted;
        // with it set, the server returns up to Maximum Items, so a short
        // page means no more matches. A usable total overrides this, so a
        // server that caps pages anyway is still followed while it reports
        // one. A short first page is the server's whole answer at offset 0.
        outcome.confirmed_complete = first_page;
        finished = true;
        break;
      }
    }

    if (!stalled && !finished && result.size() < max_ids) {
      // The batch budget ran out before the list ended.
      stalled = true;
    }
    if (!stalled) {
      return outcome;
    }

    // Retry with a single, larger page at offset 0 instead of relying on
    // offsets. Confirmed effective against Cosmian KMS: a one-shot Locate
    // with Maximum Items at or above the real number of matching objects
    // returns them all. A server whose order changes between requests is
    // handled the same way, since one page needs no stable order. The first
    // page is at least twice the ids already known and doubles each attempt,
    // capped at max_ids, so this takes O(log(max_ids)) extra requests.
    //
    // This path returns only once the list is known to be complete, and
    // throws otherwise, because a silently partial list means lost keys for
    // callers such as a keyring. Earlier versions returned a truncated list
    // instead, or for a server with an unstable order that also caps Maximum
    // Items, kept paging and returned whatever that reached. A response too
    // large for locate_response_size_limit() makes do_exchange throw, and
    // that exception propagates.
    //
    // Without a usable Located Items total, a short page is accepted as the
    // whole list when it holds every id already known. A server that ignores
    // Offset Items, reports no total and also caps Maximum Items below the
    // number of matching objects looks exactly like that, and no client can
    // enumerate such a server; this is no worse than before the fallback.
    const std::size_t known = result.size();
    std::size_t page_size = known > max_ids / 2
                              ? max_ids
                              : std::max(MAX_ITEMS_IN_BATCH * 2, known * 2);
    page_size = std::min(page_size, max_ids);
    for (;; page_size = page_size > max_ids / 2 ? max_ids : page_size * 2) {
      std::optional<std::size_t> located_items;
      const auto got = locate_page(
          by_group,
          filter,
          o_type,
          0,
          page_size,
          &located_items,
          locate_response_size_limit(page_size)
      );
      const std::size_t known_before = result.size();
      const std::unordered_set<std::string> page_ids(got.begin(), got.end());
      const auto known_in_page = static_cast<std::size_t>(std::count_if(
          page_ids.begin(), page_ids.end(), [&seen](const std::string &id) {
            return seen.contains(id);
          }
      ));
      merge_new_ids(result, seen, got, max_ids);
      auto total = located_total(located_items, got.size());
      if (!total.has_value()) {
        total = known_total;
      }

      if (result.size() >= max_ids) {
        return outcome;
      }
      if (total.has_value() && result.size() >= *total) {
        outcome.confirmed_complete = true;
        return outcome;
      }
      if (got.size() < page_size) {
        if (known_in_page < known_before) {
          throw kmipcore::KmipException(
              "Locate: a single page at offset 0 omits " +
              std::to_string(known_before - known_in_page) + " of the " +
              std::to_string(known_before) +
              " objects the server returned earlier; cannot determine the "
              "complete list"
          );
        }
        if (total.has_value()) {
          throw kmipcore::KmipException(
              "Locate: server reports " + std::to_string(*total) +
              " located objects but returned only " +
              std::to_string(result.size()) + " distinct identifiers"
          );
        }
        outcome.confirmed_complete = true;
        return outcome;
      }
      if (page_size >= max_ids) {
        throw kmipcore::KmipException(
            "Locate: server returned a full page of " +
            std::to_string(page_size) + " identifiers containing only " +
            std::to_string(result.size()) + " distinct values"
        );
      }
    }
  }

  // Recovers ids that a server without a stable global order for ungrouped
  // Locate can skip between pages, by re-querying with a few smaller page
  // sizes and deduplicating into `outcome`.
  //
  // A pass ends on a short page, or on a page that adds nothing new and
  // repeats the previous page (a server ignoring Offset Items), so it cannot
  // spend its whole batch budget re-fetching one page. The result never
  // exceeds max_ids entries, and at most probe_page_sizes.size() *
  // MAX_BATCHES_IN_SEARCH requests are made.
  void KmipClient::probe_all(
      object_type o_type, std::size_t max_ids, LocateOutcome &outcome
  ) const {
    auto &result = outcome.ids;
    static constexpr std::array<std::size_t, 3> probe_page_sizes{256, 64, 16};
    for (const auto probe_page_size : probe_page_sizes) {
      std::size_t offset = 0;
      std::vector<std::string> prev_page;
      for (std::size_t batch = 0;
           batch < MAX_BATCHES_IN_SEARCH && result.size() < max_ids;
           ++batch) {
        std::optional<std::size_t> located_items;
        auto page = locate_page(
            true,
            "",
            o_type,
            offset,
            probe_page_size,
            &located_items,
            kmipcore::RequestMessage::DEFAULT_MAX_RESPONSE_SIZE
        );
        if (page.empty()) {
          break;
        }

        const bool added_any =
            merge_new_ids(result, outcome.seen, page, max_ids);

        const auto total = located_total(located_items, page.size());
        if (total.has_value() && offset + probe_page_size >= *total) {
          break;
        }
        if (!added_any &&
            (page.size() < probe_page_size || same_ids(page, prev_page))) {
          break;
        }

        offset += probe_page_size;
        prev_page = std::move(page);
      }

      if (result.size() >= max_ids) {
        break;
      }
    }
  }

  std::vector<std::string> KmipClient::op_locate_by_group(
      const std::string &group, object_type o_type, std::size_t max_ids
  ) const {
    return locate_all(true, group, o_type, max_ids).ids;
  }

  std::vector<std::string> KmipClient::op_locate_page_by_group(
      const std::string &group,
      object_type o_type,
      std::size_t offset,
      std::size_t page_size,
      std::optional<std::size_t> *located_items
  ) const {
    return locate_page(
        true,
        group,
        o_type,
        offset,
        page_size,
        located_items,
        kmipcore::RequestMessage::DEFAULT_MAX_RESPONSE_SIZE
    );
  }

  std::vector<std::string> KmipClient::locate_page(
      bool by_group,
      const std::string &filter,
      object_type o_type,
      std::size_t offset,
      std::size_t page_size,
      std::optional<std::size_t> *located_items,
      std::size_t max_response_size
  ) const {
    if (located_items != nullptr) {
      *located_items = std::nullopt;
    }
    if (page_size == 0) {
      return {};
    }

    auto request = make_request_message();
    request.setMaxResponseSize(max_response_size);
    const auto batch_item_id = request.add_batch_item(
        kmipcore::LocateRequest(
            by_group,
            filter,
            o_type,
            page_size,
            offset,
            request.getHeader().getProtocolVersion()
        )
    );

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    auto response =
        rf.getResponseByBatchItemId<kmipcore::LocateResponseBatchItem>(
            batch_item_id
        );

    if (located_items != nullptr) {
      const auto total_items = response.getLocatePayload().getLocatedItems();
      if (total_items.has_value() && *total_items >= 0) {
        *located_items = static_cast<std::size_t>(*total_items);
      }
    }

    return std::vector<std::string>(
        response.getUniqueIdentifiers().begin(),
        response.getUniqueIdentifiers().end()
    );
  }

  std::vector<std::string>
      KmipClient::op_all(object_type o_type, std::size_t max_ids) const {
    if (max_ids == 0) {
      return {};
    }

    auto outcome = locate_all(true, "", o_type, max_ids);
    if (outcome.ids.size() >= max_ids || outcome.confirmed_complete) {
      return std::move(outcome.ids);
    }

    // The list ended normally, but nothing from the server proves it is
    // complete, and a server without a stable global order for ungrouped
    // Locate can skip ids without ever repeating one. Probe again with
    // smaller windows.
    probe_all(o_type, max_ids, outcome);
    return std::move(outcome.ids);
  }

  std::vector<std::string> KmipClient::op_all_page(
      object_type o_type,
      std::size_t offset,
      std::size_t page_size,
      std::optional<std::size_t> *located_items
  ) const {
    return op_locate_page_by_group(
        "", o_type, offset, page_size, located_items
    );
  }

  std::vector<kmipcore::ProtocolVersion>
      KmipClient::op_discover_versions() const {
    auto request = make_request_message();

    kmipcore::RequestBatchItem item;
    item.setOperation(kmipcore::KMIP_OP_DISCOVER_VERSIONS);
    item.setRequestPayload(
        kmipcore::Element::createStructure(
            kmipcore::tag::KMIP_TAG_REQUEST_PAYLOAD
        )
    );
    const auto batch_item_id = request.add_batch_item(std::move(item));

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    auto response = rf.getResponseByBatchItemId<
        kmipcore::DiscoverVersionsResponseBatchItem>(batch_item_id);
    return std::vector<kmipcore::ProtocolVersion>{
        response.getProtocolVersions().begin(),
        response.getProtocolVersions().end()
    };
  }

  KmipClient::QueryServerInfo KmipClient::op_query() const {
    auto request = make_request_message();

    kmipcore::RequestBatchItem item;
    item.setOperation(kmipcore::KMIP_OP_QUERY);

    // Create request payload with query functions
    // Request: Query Operations, Query Objects, and Query Server Information
    auto payload = kmipcore::Element::createStructure(
        kmipcore::tag::KMIP_TAG_REQUEST_PAYLOAD
    );

    // Add Query Function items for: Operations, Objects, and Server Information
    auto query_ops_elem = kmipcore::Element::createEnumeration(
        kmipcore::tag::KMIP_TAG_QUERY_FUNCTION,
        static_cast<int32_t>(kmipcore::KMIP_QUERY_OPERATIONS)
    );
    payload->asStructure()->add(query_ops_elem);

    auto query_objs_elem = kmipcore::Element::createEnumeration(
        kmipcore::tag::KMIP_TAG_QUERY_FUNCTION,
        static_cast<int32_t>(kmipcore::KMIP_QUERY_OBJECTS)
    );
    payload->asStructure()->add(query_objs_elem);

    auto query_info_elem = kmipcore::Element::createEnumeration(
        kmipcore::tag::KMIP_TAG_QUERY_FUNCTION,
        static_cast<int32_t>(kmipcore::KMIP_QUERY_SERVER_INFORMATION)
    );
    payload->asStructure()->add(query_info_elem);

    item.setRequestPayload(payload);
    const auto batch_item_id = request.add_batch_item(std::move(item));

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    const auto response =
        rf.getResponseByBatchItemId<kmipcore::QueryResponseBatchItem>(
            batch_item_id
        );

    QueryServerInfo result;
    result.supported_operations.reserve(response.getOperations().size());
    for (const auto op : response.getOperations()) {
      result.supported_operations.push_back(
          static_cast<kmipcore::operation>(op)
      );
    }
    result.supported_object_types.reserve(response.getObjectTypes().size());
    for (const auto type : response.getObjectTypes()) {
      result.supported_object_types.push_back(
          static_cast<kmipcore::object_type>(type)
      );
    }
    result.vendor_name = response.getVendorIdentification();
    result.server_name = response.getServerName();
    result.product_name = response.getProductName();
    result.server_version = response.getServerVersion();
    result.build_level = response.getBuildLevel();
    result.build_date = response.getBuildDate();
    result.server_serial_number = response.getServerSerialNumber();
    result.server_load = response.getServerLoad();
    result.cluster_info = response.getClusterInfo();
    return result;
  }

  std::string KmipClient::op_revoke(
      const std::string &id,
      revocation_reason_type reason,
      const std::string &message,
      time_t occurrence_time
  ) const {
    auto request = make_request_message();
    const auto batch_item_id = request.add_batch_item(
        kmipcore::RevokeRequest(id, reason, message, occurrence_time)
    );

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::RevokeResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  std::string KmipClient::op_destroy(const std::string &id) const {
    auto request = make_request_message();
    const auto batch_item_id =
        request.add_batch_item(kmipcore::DestroyRequest(id));

    kmipcore::secure_bytes response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::DestroyResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

}  // namespace kmipclient
