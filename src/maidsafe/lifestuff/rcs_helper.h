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

#ifndef MAIDSAFE_LIFESTUFF_RCS_HELPER_H_
#define MAIDSAFE_LIFESTUFF_RCS_HELPER_H_

#include <memory>

#include "boost/asio.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

namespace fs = boost::filesystem;
namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

#ifndef LOCAL_TARGETS_ONLY
namespace dht { class Contact; }
namespace pd { class ClientContainer; }
#endif

namespace lifestuff {

int GetValidatedMpidPublicKey(
    const std::string &public_username,
    const pcs::RemoteChunkStore::ValidationData &validation_data,
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
    asymm::PublicKey *public_key);

int GetValidatedMmidPublicKey(
    const std::string &mmid_name,
    const pcs::RemoteChunkStore::ValidationData &validation_data,
    std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
    asymm::PublicKey *public_key);

#ifdef LOCAL_TARGETS_ONLY
std::shared_ptr<priv::chunk_store::RemoteChunkStore> BuildChunkStore(
    const fs::path &buffered_chunk_store_path,
    const fs::path &local_chunk_manager_path,
    boost::asio::io_service &asio_service);
#else
std::shared_ptr<priv::chunk_store::RemoteChunkStore> BuildChunkStore(
    const fs::path &base_dir,
    std::shared_ptr<pd::ClientContainer> *client_container);

int RetrieveBootstrapContacts(const fs::path &download_dir,
                              std::vector<dht::Contact> *bootstrap_contacts);

typedef std::shared_ptr<pd::ClientContainer> ClientContainerPtr;
ClientContainerPtr SetUpClientContainer(
    const fs::path &base_dir);
#endif

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_RCS_HELPER_H_