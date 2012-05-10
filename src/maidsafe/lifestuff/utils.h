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

#ifndef MAIDSAFE_LIFESTUFF_UTILS_H_
#define MAIDSAFE_LIFESTUFF_UTILS_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/lexical_cast.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/pki/packet.h"

namespace fs = boost::filesystem;
namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace encrypt { struct DataMap; }
#ifndef LOCAL_TARGETS_ONLY
namespace dht { class Contact; }
namespace pd { class ClientContainer; }
#endif

namespace lifestuff {

enum InboxItemType {
  kChat,
  kFileTransfer,
  kContactPresence,
  kContactProfilePicture,
  kContactDeletion,
  kOpenShareInvitation,
  kShare,

  // Max
  kMaxInboxItemType = kShare
};

struct InboxItem {
  explicit InboxItem(InboxItemType inbox_item_type = kChat);

  InboxItemType item_type;
  std::string sender_public_id;
  std::string receiver_public_id;
  std::vector<std::string> content;
  std::string timestamp;
};

std::string CreatePin();

bool CheckKeywordValidity(const std::string &keyword);
bool CheckPinValidity(const std::string &pin);
bool CheckPasswordValidity(const std::string &password);

fs::path CreateTestDirectory(fs::path const& parent, std::string *tail);
int CreateTestFile(fs::path const& parent,
                   int size_in_mb,
                   std::string *file_name);

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

void SendContactInfoCallback(const bool &response,
                             boost::mutex *mutex,
                             boost::condition_variable *cond_var,
                             int *result);

int AwaitingResponse(boost::mutex *mutex,
                     boost::condition_variable *cond_var,
                     std::vector<int> *results);

std::string ComposeSignaturePacketName(const std::string &name);

std::string ComposeSignaturePacketValue(
    const maidsafe::pki::SignaturePacket &packet);

std::shared_ptr<encrypt::DataMap> ParseSerialisedDataMap(
    const std::string &serialised_data_map);

std::string PutFilenameData(const std::string &file_name);
void GetFilenameData(const std::string &content,
                     std::string *file_name,
                     std::string *serialised_data_map);
std::string GetNameInPath(const fs::path &save_path,
                          const std::string &file_name);
int CopyDir(const fs::path& source, const fs::path& dest);

int CopyDirectoryContent(const fs::path& from, const fs::path& to);

bool VerifyAndCreatePath(const fs::path& path);

std::string IsoTimeWithMicroSeconds();

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

#endif  // MAIDSAFE_LIFESTUFF_UTILS_H_
