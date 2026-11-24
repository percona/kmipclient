/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

// Deterministic tests for op_locate_by_group / op_all paging against
// simulated servers, so the stall fallback and its stop conditions are
// covered whichever real KMIP server CI happens to use.

#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClient.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/kmip_protocol.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <vector>

namespace {

  using kmipclient::KmipClient;
  using kmipclient::object_type;

  struct ServerBehavior {
    std::size_t object_count = 0;
    bool honor_offset = true;
    bool report_located_items = false;
    // Located Items set to the number of ids in each response instead of the
    // total, as Cosmian KMS does over KMIP 2.0.
    bool located_items_counts_page = false;
    // 0 means no cap on Maximum Items.
    std::size_t max_items_cap = 0;
    std::size_t id_length = 36;
    // Pages requested with more than this many items get only the first
    // `shrink_to` objects. 0 disables it.
    std::size_t shrink_above = 0;
    std::size_t shrink_to = 0;
    // Objects from this position on are rotated by `rotate_step` on every
    // request: an unstable order for all but the first part. 0 disables it.
    std::size_t rotate_from = 0;
    std::size_t rotate_step = 37;
    // Offsets above this are served as this offset. 0 disables it.
    std::size_t max_offset = 0;
    // Requests at this offset or beyond get an empty page. 0 disables it.
    std::size_t empty_from_offset = 0;
  };

  std::string make_id(std::size_t i, std::size_t length) {
    std::string id = "id-" + std::to_string(i) + "-";
    id.resize(std::max(length, id.size()), 'x');
    return id;
  }

  class FakeLocateServer final : public kmipclient::NetClient {
  public:
    // No timeout: building the multi-megabyte responses of the large cases
    // takes seconds under ASan, and that would count against the exchange.
    explicit FakeLocateServer(ServerBehavior behavior)
      : NetClient("host", "5696", "client.pem", "client.key", "ca.pem", 0),
        behavior_(behavior) {
      m_isConnected = true;
    }

    bool connect() override {
      m_isConnected = true;
      return true;
    }

    void close() override { m_isConnected = false; }

    int send(std::span<const std::uint8_t> data) override {
      pending_request_.insert(pending_request_.end(), data.begin(), data.end());
      constexpr std::size_t header = 8;
      if (pending_request_.size() >= header) {
        const std::size_t body = (std::size_t{pending_request_[4]} << 24) |
                                 (std::size_t{pending_request_[5]} << 16) |
                                 (std::size_t{pending_request_[6]} << 8) |
                                 std::size_t{pending_request_[7]};
        if (pending_request_.size() >= header + body) {
          respond();
          pending_request_.clear();
        }
      }
      return static_cast<int>(data.size());
    }

    int recv(std::span<std::uint8_t> data) override {
      const std::size_t count =
          std::min(data.size(), response_.size() - response_offset_);
      std::copy_n(response_.data() + response_offset_, count, data.data());
      response_offset_ += count;
      return static_cast<int>(count);
    }

    std::size_t requests = 0;

  private:
    void respond() {
      ++requests;
      std::size_t offset = 0;
      const auto request = kmipcore::RequestMessage::fromElement(
          kmipcore::Element::deserialize(pending_request_, offset)
      );
      const auto &item = request.getBatchItems().at(0);
      const auto payload_in = item.getRequestPayload();
      const auto offset_items =
          payload_in->getChild(kmipcore::tag::KMIP_TAG_OFFSET_ITEMS);
      const auto maximum_items =
          payload_in->getChild(kmipcore::tag::KMIP_TAG_MAXIMUM_ITEMS);

      std::size_t first = behavior_.honor_offset && offset_items
                            ? static_cast<std::size_t>(offset_items->toInt())
                            : 0;
      std::size_t count = static_cast<std::size_t>(maximum_items->toInt());
      if (behavior_.max_items_cap != 0) {
        count = std::min(count, behavior_.max_items_cap);
      }
      if (behavior_.shrink_above != 0 && count > behavior_.shrink_above) {
        count = behavior_.shrink_to;
      }
      if (behavior_.max_offset != 0) {
        first = std::min(first, behavior_.max_offset);
      }
      if (behavior_.empty_from_offset != 0 &&
          first >= behavior_.empty_from_offset) {
        count = 0;
      }
      first = std::min(first, behavior_.object_count);
      count = std::min(count, behavior_.object_count - first);

      kmipcore::LocateResponsePayload payload;
      for (std::size_t i = first; i < first + count; ++i) {
        payload.addUniqueIdentifier(make_id(object_at(i), behavior_.id_length));
      }
      if (behavior_.report_located_items) {
        payload.setLocatedItems(static_cast<int32_t>(behavior_.object_count));
      } else if (behavior_.located_items_counts_page) {
        payload.setLocatedItems(static_cast<int32_t>(count));
      }

      kmipcore::ResponseBatchItem response_item;
      response_item.setUniqueBatchItemId(item.getUniqueBatchItemId());
      response_item.setOperation(kmipcore::KMIP_OP_LOCATE);
      response_item.setResultStatus(kmipcore::KMIP_STATUS_SUCCESS);
      response_item.setResponsePayload(payload.toElement());

      kmipcore::ResponseHeader header;
      header.setProtocolVersion(request.getHeader().getProtocolVersion());
      header.setTimeStamp(0);
      header.setBatchCount(1);

      kmipcore::ResponseMessage response;
      response.setHeader(header);
      response.add_batch_item(response_item);

      kmipcore::SerializationBuffer buf;
      response.toElement()->serialize(buf);
      const auto bytes = buf.release();
      response_.assign(bytes.begin(), bytes.end());
      response_offset_ = 0;
    }

    std::size_t object_at(std::size_t position) const {
      const std::size_t from = behavior_.rotate_from;
      if (from == 0 || position < from || from >= behavior_.object_count) {
        return position;
      }
      const std::size_t rest = behavior_.object_count - from;
      return from + (position - from + requests * behavior_.rotate_step) % rest;
    }

    ServerBehavior behavior_;
    std::vector<std::uint8_t> pending_request_;
    std::vector<std::uint8_t> response_;
    std::size_t response_offset_ = 0;
  };

  std::vector<std::string> expected_ids(const ServerBehavior &behavior) {
    std::vector<std::string> ids;
    for (std::size_t i = 0; i < behavior.object_count; ++i) {
      ids.push_back(make_id(i, behavior.id_length));
    }
    std::sort(ids.begin(), ids.end());
    return ids;
  }

  std::vector<std::string> sorted(std::vector<std::string> ids) {
    std::sort(ids.begin(), ids.end());
    return ids;
  }

  std::vector<std::string> locate(FakeLocateServer &server) {
    KmipClient client(server);
    return client.op_locate_by_group(
        "group", object_type::KMIP_OBJTYPE_SYMMETRIC_KEY
    );
  }

  void expect_locate_throws(
      FakeLocateServer &server, const std::string &message_part
  ) {
    try {
      (void) locate(server);
      ADD_FAILURE() << "expected a KmipException, got a result";
    } catch (const kmipcore::KmipException &e) {
      EXPECT_NE(std::string(e.what()).find(message_part), std::string::npos)
          << "unexpected exception: " << e.what();
    }
  }

}  // namespace

TEST(LocatePagingTest, OffsetHonoringServerUsesPlainPaging) {
  const ServerBehavior behavior{.object_count = 1000};
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  // 256 + 256 + 256 + 232: the short page ends the list. No fallback.
  EXPECT_EQ(server.requests, 4u);
}

TEST(LocatePagingTest, ShortFirstPageTakesOneRequest) {
  // The common case, a search with fewer results than one page, on a server
  // that honors offsets and on one that ignores them (Cosmian KMS).
  for (const bool honor_offset : {true, false}) {
    const ServerBehavior behavior{
        .object_count = 1, .honor_offset = honor_offset
    };
    FakeLocateServer server(behavior);

    EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
    EXPECT_EQ(server.requests, 1u);
  }
}

TEST(LocatePagingTest, ServerCappingPagesWithoutTotalIsTakenAtItsWord) {
  // KMIP allows a server-side page limit only when Maximum Items is omitted;
  // with it set, a short page means no more matches. A server that caps
  // pages anyway and reports no total therefore ends the search early. This
  // pins that trade-off: following such a server would cost every other
  // search an extra request.
  const ServerBehavior behavior{.object_count = 1000, .max_items_cap = 100};
  FakeLocateServer server(behavior);

  EXPECT_EQ(locate(server).size(), 100u);
  EXPECT_EQ(server.requests, 1u);
}

TEST(LocatePagingTest, OffsetIgnoringServerWithTotalJustAboveOnePage) {
  // The repeated second page brings the offset past the reported total of
  // 300 while only 256 ids are known; the total proves ids are missing.
  const ServerBehavior behavior{
      .object_count = 300, .honor_offset = false, .report_located_items = true
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  EXPECT_EQ(server.requests, 3u);
}

TEST(LocatePagingTest, OffsetIgnoringServerReturningVaryingPages) {
  // Offsets ignored, and each response is a different window of the
  // objects, so no two pages are the same. The search must still notice
  // when pages stop adding ids instead of running its whole batch budget.
  const ServerBehavior behavior{
      .object_count = 1000, .honor_offset = false, .rotate_from = 1
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  EXPECT_LT(server.requests, 50u);
}

TEST(LocatePagingTest, LongIdsFitFallbackPages) {
  // 3000-byte ids: fallback pages get the same allowance per id as a regular
  // 256-item page, so the 512-item page holding all 400 objects (~1.2 MB)
  // is received.
  const ServerBehavior behavior{
      .object_count = 400, .honor_offset = false, .id_length = 3000
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  EXPECT_EQ(server.requests, 3u);
}

TEST(LocatePagingTest, OffsetIgnoringServerSmallGroupIsComplete) {
  const ServerBehavior behavior{.object_count = 300, .honor_offset = false};
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  // A first page of 256, the same page again (the stall), then one fallback
  // page of 512 holding all 300.
  EXPECT_EQ(server.requests, 3u);
}

TEST(LocatePagingTest, OffsetIgnoringServerLargeGroupIsComplete) {
  const ServerBehavior behavior{.object_count = 20000, .honor_offset = false};
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  // A first page, the same page again, then fallback pages of 512 .. 32768.
  EXPECT_EQ(server.requests, 9u);
}

TEST(LocatePagingTest, OffsetIgnoringServerGroupOfExactlyOnePage) {
  // Indistinguishable from a server capping Maximum Items at 256: treated as
  // complete, which is what it is on Cosmian.
  const ServerBehavior behavior{.object_count = 256, .honor_offset = false};
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  EXPECT_EQ(server.requests, 3u);
}

TEST(LocatePagingTest, OffsetIgnoringServerWithLocatedItemsIsComplete) {
  const ServerBehavior behavior{
      .object_count = 1000, .honor_offset = false, .report_located_items = true
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
}

TEST(LocatePagingTest, OffsetHonoringServerStopsAtReportedTotal) {
  const ServerBehavior behavior{
      .object_count = 512, .report_located_items = true
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  // The second full page reaches the reported total of 512.
  EXPECT_EQ(server.requests, 2u);
}

TEST(LocatePagingTest, OffsetHonoringServerWithTotalOfOnePage) {
  // A total equal to the page size isn't trusted (see the next tests), so
  // this costs one extra request that comes back empty.
  const ServerBehavior behavior{
      .object_count = 256, .report_located_items = true
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  EXPECT_EQ(server.requests, 2u);
}

TEST(LocatePagingTest, LocatedItemsCountingOnlyThePageIsIgnored) {
  // Cosmian KMS over KMIP 2.0: offset ignored, Located Items = page count.
  const ServerBehavior behavior{
      .object_count = 300,
      .honor_offset = false,
      .located_items_counts_page = true
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  EXPECT_EQ(server.requests, 3u);
}

TEST(LocatePagingTest, LocatedItemsCountingOnlyThePageInFallback) {
  // The 512-item fallback page reports 512 located; trusting that would
  // return half of the group.
  const ServerBehavior behavior{
      .object_count = 1000,
      .honor_offset = false,
      .located_items_counts_page = true
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  EXPECT_EQ(server.requests, 4u);
}

TEST(LocatePagingTest, FallbackHonorsMaxIds) {
  const ServerBehavior behavior{.object_count = 1000, .honor_offset = false};
  FakeLocateServer server(behavior);
  KmipClient client(server);

  const auto ids = client.op_locate_by_group(
      "group", object_type::KMIP_OBJTYPE_SYMMETRIC_KEY, 300
  );
  EXPECT_EQ(ids.size(), 300u);
  const auto unique_ids = sorted(ids);
  EXPECT_EQ(
      std::adjacent_find(unique_ids.begin(), unique_ids.end()), unique_ids.end()
  );
}

TEST(LocatePagingTest, ThrowsWhenServerCapsAndReportsMoreItems) {
  const ServerBehavior behavior{
      .object_count = 1000,
      .honor_offset = false,
      .report_located_items = true,
      .max_items_cap = 256
  };
  FakeLocateServer server(behavior);

  expect_locate_throws(
      server, "server reports 1000 located objects but returned only 256"
  );
}

TEST(LocatePagingTest, ThrowsWhenLargerPageReturnsFewerObjects) {
  const ServerBehavior behavior{
      .object_count = 1000,
      .honor_offset = false,
      .shrink_above = 256,
      .shrink_to = 100
  };
  FakeLocateServer server(behavior);

  expect_locate_throws(server, "omits 156 of the 256");
}

TEST(LocatePagingTest, ThrowsInsteadOfTruncatingWhenResponseTooLarge) {
  // 6000 objects with 3000-byte ids (~18 MB in one page). The fallback pages
  // of 512 .. 4096 fit their limits; the 8192-item page would need more than
  // the 16 MiB KMIP_MAX_MESSAGE_HARD_LIMIT, so the search fails instead of
  // returning the 4096 ids it has.
  const ServerBehavior behavior{
      .object_count = 6000, .honor_offset = false, .id_length = 3000
  };
  FakeLocateServer server(behavior);

  expect_locate_throws(server, "Message too long");
  EXPECT_EQ(server.requests, 7u);
}

TEST(LocatePagingTest, GetAllAgainstOffsetIgnoringServerStaysCheap) {
  const ServerBehavior behavior{.object_count = 1000, .honor_offset = false};
  FakeLocateServer server(behavior);
  KmipClient client(server);

  EXPECT_EQ(
      sorted(client.op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY)),
      expected_ids(behavior)
  );
  // A first page, the same page again, then fallback pages of 512 and 1024.
  // The fallback confirms the list, so op_all skips its probe passes.
  EXPECT_EQ(server.requests, 4u);
}

TEST(LocatePagingTest, UnstableOrderIsRecoveredBySinglePage) {
  // Offsets honored, but everything after the first 256 objects is rotated
  // on every request, so plain paging skips some ids and repeats others. A
  // repeated id sends the search to the single-page fallback, which needs
  // no stable order.
  const ServerBehavior behavior{.object_count = 1000, .rotate_from = 256};
  FakeLocateServer group_server(behavior);
  EXPECT_EQ(sorted(locate(group_server)), expected_ids(behavior));

  FakeLocateServer all_server(behavior);
  EXPECT_EQ(
      sorted(
          KmipClient(all_server).op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY)
      ),
      expected_ids(behavior)
  );
}

TEST(LocatePagingTest, GetAllProbesWhenNothingConfirmsTheList) {
  // A consistent server without Located Items and more than one page of
  // objects: nothing proves the list complete, so op_all re-reads it with
  // pages of 256, 64 and 16, as before this change.
  const ServerBehavior behavior{.object_count = 300};
  FakeLocateServer server(behavior);
  KmipClient client(server);

  EXPECT_EQ(
      sorted(client.op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY)),
      expected_ids(behavior)
  );
  // Search: 256, 44. Probe passes end on their short page:
  // 256-pass 2, 64-pass 5, 16-pass 19 requests.
  EXPECT_EQ(server.requests, 28u);
}

TEST(LocatePagingTest, GetAllSmallListTakesOneRequest) {
  // A single short page at offset 0 is the server's whole answer, so op_all
  // skips its probe passes.
  const ServerBehavior behavior{.object_count = 100};
  FakeLocateServer server(behavior);
  KmipClient client(server);

  EXPECT_EQ(
      sorted(client.op_all(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY)),
      expected_ids(behavior)
  );
  EXPECT_EQ(server.requests, 1u);
}

TEST(LocatePagingTest, EmptyPageBelowReportedTotal) {
  // The server reports 600 objects but stops serving pages after offset
  // 256. The search must not stop at the empty page with 256 ids.
  const ServerBehavior behavior{
      .object_count = 600,
      .report_located_items = true,
      .empty_from_offset = 256
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  // 256, empty, then fallback pages of 512 and 1024.
  EXPECT_EQ(server.requests, 4u);
}

TEST(LocatePagingTest, ThrowsWhenRequestBudgetRunsOut) {
  // One id per page, with a total that keeps the search going: 256 requests
  // collect only 256 of 300 ids, and the fallback page is capped too.
  const ServerBehavior behavior{
      .object_count = 300, .report_located_items = true, .max_items_cap = 1
  };
  FakeLocateServer server(behavior);

  expect_locate_throws(server, "omits 255 of the 256");
}

TEST(LocatePagingTest, ThrowsWhenSinglePageOmitsKnownIds) {
  // Unstable order plus a 300-item cap: the capped single page cannot hold
  // the ids already seen, which the search must report instead of merging.
  const ServerBehavior behavior{
      .object_count = 400, .max_items_cap = 300, .rotate_from = 1
  };
  FakeLocateServer server(behavior);

  expect_locate_throws(server, "objects the server returned earlier");
}

TEST(LocatePagingTest, OffsetHonoringServerCappingPagesReportsTotal) {
  // Maximum Items capped at 100, with a correct total: short pages must not
  // end the search while the total says more objects exist.
  const ServerBehavior behavior{
      .object_count = 1000, .report_located_items = true, .max_items_cap = 100
  };
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  EXPECT_EQ(server.requests, 10u);
}

TEST(LocatePagingTest, FallbackStartsAboveIdsAlreadyKnown) {
  // The server honors offsets up to 512 and repeats that page for larger
  // ones, so the stall comes after 768 ids. A first fallback page of 512
  // would be smaller than what is already known.
  const ServerBehavior behavior{.object_count = 1000, .max_offset = 512};
  FakeLocateServer server(behavior);

  EXPECT_EQ(sorted(locate(server)), expected_ids(behavior));
  // Pages at 0, 256, 512, the repeat, then one fallback page of 1536.
  EXPECT_EQ(server.requests, 5u);
}

TEST(LocatePagingTest, NameSearchUsesTheSamePaging) {
  const ServerBehavior behavior{.object_count = 300, .honor_offset = false};
  FakeLocateServer server(behavior);
  KmipClient client(server);

  const auto ids =
      client.op_locate_by_name("name", object_type::KMIP_OBJTYPE_SYMMETRIC_KEY);
  EXPECT_EQ(ids.size(), behavior.object_count);
  EXPECT_EQ(sorted(ids), expected_ids(behavior));
  EXPECT_EQ(server.requests, 3u);
}
