/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include "maidsafe/lifestuff/rcs_helper.h"

#include <fstream>  // NOLINT (Fraser)
#include <iostream>  // NOLINT (Fraser)
#include <istream>  // NOLINT (Fraser)
#include <ostream>  // NOLINT (Fraser)
#include <string>
#include <vector>

#include "boost/archive/text_iarchive.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/node.h"
#include "maidsafe/pd/client/utils.h"
#endif

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace pca = maidsafe::priv::chunk_actions;
namespace bai = boost::asio::ip;

namespace maidsafe {

namespace lifestuff {

#ifdef LOCAL_TARGETS_ONLY
std::shared_ptr<pcs::RemoteChunkStore> BuildChunkStore(const fs::path& buffered_chunk_store_path,
                                                       const fs::path& local_chunk_manager_path,
                                                       boost::asio::io_service& asio_service) {
  boost::system::error_code error_code;
  fs::create_directories(local_chunk_manager_path / "lock", error_code);
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store(
      pcs::CreateLocalChunkStore(buffered_chunk_store_path,
                                 local_chunk_manager_path,
                                 local_chunk_manager_path / "lock",
                                 asio_service));
  return remote_chunk_store;
}
#else
std::shared_ptr<pcs::RemoteChunkStore> BuildChunkStore(const fs::path& base_dir,
                                                       std::shared_ptr<pd::Node>* node) {
  BOOST_ASSERT(node);
  *node = SetupNode(base_dir);
  if (*node) {
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store(
        new pcs::RemoteChunkStore((*node)->chunk_store(),
                                  (*node)->chunk_manager(),
                                  (*node)->chunk_action_authority()));
    remote_chunk_store->SetMaxActiveOps(32);
    return remote_chunk_store;
  } else {
    LOG(kError) << "Failed to initialise RemoteChunkStore.";
    return nullptr;
  }
}

int RetrieveBootstrapContacts(const fs::path& download_dir) {
  std::ostringstream bootstrap_stream(std::ios::binary);
  try {
    boost::asio::io_service io_service;

    // Get a list of endpoints corresponding to the server name.
    bai::tcp::resolver resolver(io_service);
//     bai::tcp::resolver::query query("96.126.103.209", "http");
//     bai::tcp::resolver::query query("127.0.0.1", "http");
    bai::tcp::resolver::query query("192.168.1.119", "http");
    bai::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

    // Try each endpoint until we successfully establish a connection.
    bai::tcp::socket socket(io_service);
    boost::asio::connect(socket, endpoint_iterator);

    // Form the request. We specify the "Connection: close" header so that the
    // server will close the socket after transmitting the response. This will
    // allow us to treat all data up until the EOF as the content.
    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "GET /bootstrap HTTP/1.0\r\n";
    request_stream << "Host: LifeStuffTest\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: close\r\n\r\n";

    // Send the request.
    boost::asio::write(socket, request);

    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\r\n");

    // Check that response is OK.
    std::istream response_stream(&response);
    std::string http_version;
    response_stream >> http_version;
    unsigned int status_code;
    response_stream >> status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
      LOG(kError) << "Error downloading bootstrap file: Invalid response";
      return kGeneralError;
    }
    if (status_code != 200) {
      LOG(kError) << "Error downloading bootstrap file: Response returned "
                  << "with status code " << status_code;
      return kGeneralError;
    }

    // Read the response headers, which are terminated by a blank line.
    boost::asio::read_until(socket, response, "\r\n\r\n");

    // Process the response headers.
    std::string header;
    while (std::getline(response_stream, header)) {
      if (header == "\r")
        break;
    }

    // Write whatever content we already have to output.
    if (response.size() > 0)
      bootstrap_stream << &response;

    // Read until EOF, writing data to output as we go.
    boost::system::error_code error;
    while (boost::asio::read(socket, response, boost::asio::transfer_at_least(1), error))
      bootstrap_stream << &response;

    if (error != boost::asio::error::eof) {
      LOG(kError) << "Error downloading bootstrap file: " << error.message();
      return error.value();
    }
  }
  catch(const std::exception& e) {
    LOG(kError) << "Exception: " << e.what();
    return kGeneralException;
  }

  fs::path bootstrap_file(download_dir / "bootstrap");
  WriteFile(bootstrap_file, bootstrap_stream.str());

  return kSuccess;
}

std::shared_ptr<pd::Node> SetupNode(const fs::path& base_dir) {
  auto node = std::make_shared<pd::Node>();

  // TODO(Team) Move bootstrap file to where Routing can find it
  int result = RetrieveBootstrapContacts(base_dir);
  if (result != kSuccess) {
    LOG(kError) << "Failed to retrieve bootstrap contacts.  Result: " << result;
    return nullptr;
  }

  result = node->Start(base_dir / "buffered_chunk_store");
  if (result != kSuccess) {
    LOG(kError) << "Failed to start PD node.  Result: " << result;
    return nullptr;
  }

  LOG(kInfo) << "Started PD node.";
  return node;
}
#endif

}  // namespace lifestuff

}  // namespace maidsafe
