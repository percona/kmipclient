/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */
#ifndef KMIP_CLIENT_HPP
#define KMIP_CLIENT_HPP

#include "kmipclient/Key.hpp"
#include "kmipclient/NetClient.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_attributes.hpp"
#include "kmipcore/kmip_logger.hpp"
#include "kmipcore/kmip_protocol.hpp"

#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace kmipcore {
  class GetResponseBatchItem;
}  // namespace kmipcore

namespace kmipclient {

  /** Maximum number of KMIP locate response batches processed by search
   * helpers. */
  constexpr size_t MAX_BATCHES_IN_SEARCH = 256;
  /** Maximum number of response items expected per single KMIP batch. */
  constexpr size_t MAX_ITEMS_IN_BATCH = 256;

  class IOUtils;
  /**
   * @brief High-level KMIP client API for key and secret lifecycle operations.
   *
   * The instance uses an already configured and connected @ref NetClient
   * transport and provides typed wrappers around common KMIP operations.
   */
  class KmipClient {
  public:
    /**
     * @brief Creates a client bound to an existing transport.
     * @param net_client Pre-initialized network transport implementation.
     * @param logger Optional KMIP protocol logger. When set, serialized TTLV
     * request and response payloads are logged at DEBUG level.
     * @param version KMIP protocol version to use for requests.
     * @param close_on_destroy When true, closes the transport on client
     *        destruction. Defaults to false for this non-owning overload.
     */
    explicit KmipClient(
        NetClient &net_client,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        bool close_on_destroy = false
    );

    /**
     * @brief Creates a client that shares ownership of the transport.
     *
     * This overload helps migration from pointer-centric wrappers: callers can
     * keep and pass `std::shared_ptr<KmipClient>`/`std::shared_ptr<NetClient>`
     * handles instead of owning client objects by value.
     *
     * @param net_client Shared transport; must not be null.
     * @param logger Optional KMIP protocol logger.
     * @param version KMIP protocol version to use for requests.
     * @param close_on_destroy When true (default), closes the transport on
     *        client destruction. Set to false to keep transport alive after
     *        client destruction.
     * @throws std::invalid_argument when @p net_client is null.
     */
    explicit KmipClient(
        std::shared_ptr<NetClient> net_client,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        bool close_on_destroy = true
    );

    /**
     * @brief Convenience factory for reference-based integrations.
     *
     * Defaults to non-owning close behavior (`close_on_destroy=false`) to
     * mirror the `NetClient&` constructor.
     */
    [[nodiscard]] static std::shared_ptr<KmipClient> create_shared(
        NetClient &net_client,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        bool close_on_destroy = false
    );

    /**
     * @brief Convenience factory that keeps transport ownership shared.
     */
    [[nodiscard]] static std::shared_ptr<KmipClient> create_shared(
        std::shared_ptr<NetClient> net_client,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        bool close_on_destroy = true
    );

    /** @brief Destroys the client and internal helpers. */
    ~KmipClient();
    // non-copyable, move-only
    KmipClient(const KmipClient &) = delete;
    KmipClient &operator=(const KmipClient &) = delete;
    KmipClient(KmipClient &&other) noexcept;
    KmipClient &operator=(KmipClient &&other) noexcept;

    /**
     * @brief Executes KMIP Register for a key object.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @param k Key material and metadata to register.
     * @return Unique identifier assigned by the KMIP server.
     * @throws kmipcore::KmipException on protocol or server-side failure, or
     * for a symmetric key without a Cryptographic Algorithm defined in the
     * client's KMIP version (raw key material does not carry it).
     */
    [[nodiscard]] std::string op_register_key(
        const std::string &name, const std::string &group, const Key &k
    ) const;

    /**
     * @brief Executes KMIP Register for Secret Data.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @param secret Secret payload and type descriptor.
     * @return Unique identifier assigned by the KMIP server.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::string op_register_secret(
        const std::string &name, const std::string &group, const Secret &secret
    ) const;

    /**
     * @brief Executes KMIP Create to generate a server-side AES key.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @param key_size AES key size (typed constants: AES_128/AES_192/AES_256).
     * @param usage_mask Cryptographic Usage Mask bits to assign to the key.
     * @return Unique identifier of the created key.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::string op_create_aes_key(
        const std::string &name,
        const std::string &group,
        aes_key_size key_size = aes_key_size::AES_256,
        cryptographic_usage_mask usage_mask =
            static_cast<cryptographic_usage_mask>(
                kmipcore::KMIP_CRYPTOMASK_ENCRYPT |
                kmipcore::KMIP_CRYPTOMASK_DECRYPT
            )
    ) const;

    /**
     * @brief Executes KMIP Get and decodes a key object.
     *
     * Asymmetric keys are returned as PKCS#8 (private) or X.509
     * SubjectPublicKeyInfo (public), the formats Register declares by
     * default. When the server's default format differs, the key is asked
     * for again in those formats: up to two more Get requests. A server need
     * not convert (KMIP 1.4 §4.11); if it refuses, the key keeps the
     * server's own byte format, which Key::key_format() records.
     * @param id Unique identifier of the key object.
     * @param all_attributes When true, fetches all available attributes.
     * @return Decoded key object.
     * @throws kmipcore::KmipException on protocol or server-side failure;
     * KMIP_OBJECT_MISMATCH when a response is for another object (a
     * response without a Unique Identifier is not checked);
     * KMIP_INVALID_ENCODING when a symmetric key states no Cryptographic
     * Length, its material does not match it, or its Key Block and its
     * attributes state different algorithms or lengths;
     * KMIP_NOT_IMPLEMENTED for a key the server returns only in a
     * Transparent Key Format Type, which holds no byte encoding.
     */
    [[nodiscard]] std::unique_ptr<Key>
        op_get_key(const std::string &id, bool all_attributes = false) const;

    /**
     * @brief Executes KMIP Get and decodes a secret object.
     * @param id Unique identifier of the secret object.
     * @param all_attributes When true, fetches all available attributes.
     * @return Decoded secret object.
     * @throws kmipcore::KmipException on protocol or server-side failure;
     * KMIP_OBJECT_MISMATCH when a response is for another object (a Get
     * Attributes response without a Unique Identifier is not checked).
     */
    [[nodiscard]] Secret
        op_get_secret(const std::string &id, bool all_attributes = false) const;

    /**
     * @brief Executes KMIP Activate for a managed object.
     * @param id Unique identifier of the object to activate.
     * @return Identifier returned by the server (normally equals @p id).
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::string op_activate(const std::string &id) const;

    /**
     * @brief Executes KMIP Get Attribute List.
     * @param id Unique identifier of the target object.
     * @return List of attribute names available for the object.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::vector<std::string>
        op_get_attribute_list(const std::string &id) const;

    /**
     * @brief Executes KMIP Get Attributes for selected attribute names.
     * @param id Unique identifier of the target object.
     * @param attr_names Attribute names to fetch (for example "Name", "State").
     * @return Type-safe @ref Attributes bag with the requested attributes.
     * @throws kmipcore::KmipException on protocol or server-side failure;
     * KMIP_OBJECT_MISMATCH when the response is for another object (a
     * response without a Unique Identifier is not checked).
     */
    [[nodiscard]] kmipcore::Attributes op_get_attributes(
        const std::string &id, const std::vector<std::string> &attr_names
    ) const;

    /**
     * @brief Executes KMIP Locate using an exact object name filter.
     *
     * Pages through results the same way as op_locate_by_group(), with the
     * same deduplication, fallback and failure behavior.
     *
     * @param name Object name to match.
     * @param o_type KMIP object type to search.
     * @return Distinct matching object identifiers, at most
     *         MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH of them.
     * @throws kmipcore::KmipException on protocol or server-side failure, or
     *         when the complete list cannot be determined (see
     *         op_locate_by_group()).
     */
    [[nodiscard]] std::vector<std::string>
        op_locate_by_name(const std::string &name, object_type o_type) const;

    /**
     * @brief Executes KMIP Locate using the object group filter.
     *
     * Pages with Offset Items and deduplicates the ids. A page with fewer
     * ids than requested ends the search, as KMIP specifies, unless a usable
     * Located Items total says more objects exist. Located Items is used
     * only when it exceeds the page it came with, since some servers report
     * the page count there instead of the total. When a page repeats ids
     * already seen (the server ignores Offset Items, or its order changed), a
     * usable total shows ids are still missing, or the request budget runs out,
     * the search retries with a single, larger page at offset 0. Result size
     * and request count stay bounded by @p max_ids whatever the server does.
     *
     * @param group Group name to match.
     * @param o_type KMIP object type to search.
     * @param max_ids Upper bound on collected IDs across locate batches.
     * @return Distinct matching object identifiers, up to @p max_ids entries.
     * @throws kmipcore::KmipException on protocol or server-side failure, or
     *         when the retry cannot confirm the list is complete: the
     *         response would exceed the response-size limit, or the server
     *         contradicts itself. A partial list is never returned from that
     *         path.
     */
    [[nodiscard]] std::vector<std::string> op_locate_by_group(
        const std::string &group,
        object_type o_type,
        std::size_t max_ids = MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH
    ) const;

    /**
     * @brief Executes one paged KMIP Locate request using object group filter.
     * @param group Group name to match; empty string disables group filtering.
     * @param o_type KMIP object type to search.
     * @param offset Number of initial matches to skip.
     * @param page_size Maximum number of IDs requested for this page.
     * @param located_items Optional output with total located item count from
     *        response payload when available and non-negative; set to
     *        std::nullopt otherwise.
     * @return IDs from exactly one Locate response page.
     *
     * When @p page_size is zero, returns an empty vector and sets
     * @p located_items to std::nullopt (if provided).
     */
    [[nodiscard]] std::vector<std::string> op_locate_page_by_group(
        const std::string &group,
        object_type o_type,
        std::size_t offset,
        std::size_t page_size,
        std::optional<std::size_t> *located_items = nullptr
    ) const;

    /**
     * @brief Executes KMIP Revoke for a managed object.
     * @param id Unique identifier of the object to revoke.
     * @param reason KMIP revocation reason code.
     * @param message Optional human-readable revocation message.
     * @param occurrence_time Incident time for reasons that require it; use 0
     * for regular deactivation flows.
     * @return Identifier returned by the server (normally equals @p id).
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::string op_revoke(
        const std::string &id,
        revocation_reason_type reason,
        const std::string &message,
        time_t occurrence_time
    ) const;

    /**
     * @brief Executes KMIP Destroy for a managed object.
     * @param id Unique identifier of the object to destroy.
     * @return Identifier returned by the server (normally equals @p id).
     * @throws kmipcore::KmipException on protocol or server-side failure.
     * @note Most KMIP servers require the object to be revoked first.
     */
    [[nodiscard]] std::string op_destroy(const std::string &id) const;

    /**
     * @brief Executes KMIP Locate without name/group filters.
     *
     * Pages like op_locate_by_group(). Unless the server's data confirms the
     * list is complete, it then re-queries with smaller page sizes to catch
     * ids that a server without a stable order can skip between pages.
     *
     * @param o_type KMIP object type to fetch.
     * @param max_ids Upper bound on collected IDs across locate batches.
     * @return Distinct identifiers of matching objects, up to @p max_ids
     *         entries.
     * @throws kmipcore::KmipException on protocol or server-side failure, or
     *         when the complete list cannot be determined (see
     *         op_locate_by_group()).
     */
    [[nodiscard]] std::vector<std::string> op_all(
        object_type o_type,
        std::size_t max_ids = MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH
    ) const;

    /**
     * @brief Executes one paged KMIP Locate request without name/group
     * filters.
     * @param o_type KMIP object type to fetch.
     * @param offset Number of initial matches to skip.
     * @param page_size Maximum number of IDs requested for this page.
     * @param located_items Optional output with total located item count from
     *        response payload when available and non-negative; set to
     *        std::nullopt otherwise.
     * @return IDs from exactly one Locate response page.
     *
     * When @p page_size is zero, returns an empty vector and sets
     * @p located_items to std::nullopt (if provided).
     */
    [[nodiscard]] std::vector<std::string> op_all_page(
        object_type o_type,
        std::size_t offset,
        std::size_t page_size,
        std::optional<std::size_t> *located_items = nullptr
    ) const;

    /**
     * @brief Executes KMIP Discover Versions to query supported protocol
     * versions.
     *
     * @return Ordered list of KMIP protocol versions supported by the server.
     *         An empty list means the server returned no version information.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::vector<kmipcore::ProtocolVersion>
        op_discover_versions() const;

    /** @brief Holds server information and capabilities returned by op_query().
     */
    struct QueryServerInfo {
      std::vector<kmipcore::operation>
          supported_operations;  ///< Operations supported by server
      std::vector<kmipcore::object_type>
          supported_object_types;        ///< Object types supported by server
      std::string server_name;           ///< Human-readable server name
      std::string vendor_name;           ///< Vendor identification string
      std::string product_name;          ///< Product name
      std::string server_version;        ///< Server version string
      std::string build_level;           ///< Build level
      std::string build_date;            ///< Build date
      std::string server_serial_number;  ///< Server serial number
      std::string server_load;           ///< Current server load
      std::string cluster_info;          ///< Cluster information
    };

    /**
     * @brief Executes KMIP Query to get server information and capabilities.
     *
     * Queries the server for its capabilities and vendor-specific information.
     * Returns supported operations, object types, and server metadata.
     *
     * @return Structure containing server information and capabilities.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] QueryServerInfo op_query() const;

    /** @brief Returns the configured KMIP protocol version. */
    [[nodiscard]] const kmipcore::ProtocolVersion &
        protocol_version() const noexcept {
      return version_;
    }

    /** @brief Replaces the configured KMIP protocol version for subsequent
     * requests. */
    void set_protocol_version(kmipcore::ProtocolVersion version) noexcept {
      version_ = version;
    }

    /**
     * @brief Queries the close_on_destroy setting.
     * @return true if the transport will be closed on destruction, false
     * otherwise.
     */
    [[nodiscard]] bool close_on_destroy() const noexcept {
      return close_on_destroy_;
    }

  private:
    NetClient *net_client = nullptr;
    std::shared_ptr<NetClient> net_client_owner_;
    std::unique_ptr<IOUtils> io;
    kmipcore::ProtocolVersion version_;
    bool close_on_destroy_ = true;

    [[nodiscard]] kmipcore::RequestMessage make_request_message() const {
      return kmipcore::RequestMessage(version_);
    }

    struct LocateOutcome {
      std::vector<std::string> ids;
      // The same ids, for deduplicating further pages.
      std::unordered_set<std::string> seen;
      // True only when the server's own data proves the list is complete: a
      // usable Located Items total was reached, or a single short page at
      // offset 0 returned everything. Reaching the end of a list that took
      // several pages does not count.
      bool confirmed_complete = false;
    };

    [[nodiscard]] LocateOutcome locate_all(
        bool by_group,
        const std::string &filter,
        object_type o_type,
        std::size_t max_ids
    ) const;

    void probe_all(
        object_type o_type, std::size_t max_ids, LocateOutcome &outcome
    ) const;

    [[nodiscard]] std::vector<std::string> locate_page(
        bool by_group,
        const std::string &filter,
        object_type o_type,
        std::size_t offset,
        std::size_t page_size,
        std::optional<std::size_t> *located_items,
        std::size_t max_response_size
    ) const;

    [[nodiscard]] std::unique_ptr<Key> key_from_get_response(
        const std::string &id, const kmipcore::GetResponseBatchItem &response
    ) const;
  };

}  // namespace kmipclient

#endif  // KMIP_CLIENT_HPP
