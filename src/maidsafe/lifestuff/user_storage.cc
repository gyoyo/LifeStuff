/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Version:      1.0
* Created:      2011-04-18
* Author:       Team
* Company:      maidsafe.net limited
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

#include "maidsafe/lifestuff/user_storage.h"

#include <limits>
#include <list>

#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryptor.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/message_handler.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"
#include "maidsafe/lifestuff/version.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace {

struct InsertShareTag;
struct RemoveShareTag;
struct UpdateShareTag;
struct MemberAccessTag;
struct LeaveShareTag;

template<typename Operation>
struct AddMessageDetails {};

template<>
struct AddMessageDetails<InsertShareTag> {
  void operator()(const fs::path& path,
                  const std::string& directory_id,
                  const std::string&,
                  InboxItem* admin_message,
                  InboxItem* non_admin_message) {
    admin_message->content.push_back("insert_share");
    admin_message->content.push_back(path.filename().string());
    admin_message->content.push_back(directory_id);
    non_admin_message->content.push_back("insert_share");
    non_admin_message->content.push_back(path.filename().string());
    non_admin_message->content.push_back(directory_id);
  }
};

template<>
struct AddMessageDetails<RemoveShareTag> {
  void operator()(const fs::path&,
                  const std::string&,
                  const std::string&,
                  InboxItem* admin_message,
                  InboxItem* non_admin_message) {
    admin_message->content.push_back("remove_share");
    non_admin_message->content.push_back("remove_share");
  }
};

template<>
struct AddMessageDetails<UpdateShareTag> {
  void operator()(const fs::path&,
                  const std::string& directory_id,
                  const std::string& new_share_id,
                  InboxItem* admin_message,
                  InboxItem* non_admin_message) {
    admin_message->content.push_back("update_share");
    admin_message->content.push_back(directory_id);
    admin_message->content.push_back(new_share_id);
    non_admin_message->content.push_back("update_share");
    non_admin_message->content.push_back(directory_id);
    non_admin_message->content.push_back(new_share_id);
  }
};

template<>
struct AddMessageDetails<MemberAccessTag> {
  void operator()(const fs::path&,
                  const std::string&,
                  const std::string&,
                  InboxItem* admin_message,
                  InboxItem* non_admin_message) {
    admin_message->content.push_back("member_access");
    non_admin_message->content.push_back("member_access");
  }
};

template<>
struct AddMessageDetails<LeaveShareTag> {
  void operator()(const fs::path&,
                  const std::string&,
                  const std::string&,
                  InboxItem* admin_message,
                  InboxItem* non_admin_message) {
    admin_message->content.push_back("leave_share");
    non_admin_message->content.push_back("leave_share");
  }
};

}  // namespace

UserStorage::UserStorage(
    std::shared_ptr<pcs::RemoteChunkStore> chunk_store,
    std::shared_ptr<MessageHandler> message_handler)
    : mount_status_(false),
      chunk_store_(chunk_store),
      drive_in_user_space_(),
      session_(),
      message_handler_(message_handler),
      mount_dir_(),
      mount_thread_() {}

void UserStorage::MountDrive(const fs::path &mount_dir_path,
                             std::shared_ptr<Session> session,
                             bool creation,
                             const std::string &drive_logo) {
  DLOG(INFO) << "UserStorage::MountDrive\n";
  if (mount_status_)
    return;
  if (!fs::exists(mount_dir_path))
    fs::create_directory(mount_dir_path);

  session_ = session;
  asymm::Keys key_ring;
  key_ring.identity = session->passport_->PacketName(passport::kPmid, true);
  key_ring.public_key =
      session->passport_->SignaturePacketValue(passport::kPmid, true);
  key_ring.private_key = session->passport_->PacketPrivateKey(passport::kPmid,
                                                              true);
  key_ring.validation_token =
      session->passport_->PacketSignature(passport::kPmid, true);
  drive_in_user_space_.reset(new MaidDriveInUserSpace(chunk_store_, key_ring));

  int n(0);
  if (creation) {
    session->set_unique_user_id(
        crypto::Hash<crypto::SHA512>(session->session_name()));
    n = drive_in_user_space_->Init(session->unique_user_id(), "");
    session->set_root_parent_id(drive_in_user_space_->root_parent_id());
  } else {
    n = drive_in_user_space_->Init(session->unique_user_id(),
                                   session->root_parent_id());
  }
  DLOG(INFO) << "drive_in_user_space_ Init: " << n;

#ifdef WIN32
  std::uint32_t drive_letters, mask = 0x4, count = 2;
  drive_letters = GetLogicalDrives();
  while ((drive_letters & mask) != 0) {
    mask <<= 1;
    ++count;
  }
  if (count > 25) {
    DLOG(ERROR) << "No available drive letters:";
    return;
  }

  char drive_name[3] = {'A' + static_cast<char>(count), ':', '\0'};
  mount_dir_ = drive_name;
  int result(drive_in_user_space_->Mount(mount_dir_, drive_logo));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to Mount Drive: " << result;
    return;
  }
#else
  mount_dir_ = mount_dir_path;
//   boost::thread(std::bind(&MaidDriveInUserSpace::Mount,
//                           drive_in_user_space_,
//                           mount_dir_,
//                           drive_logo,
//                           false));
  mount_thread_.reset(new boost::thread(
                              std::bind(&MaidDriveInUserSpace::Mount,
                              drive_in_user_space_,
                              mount_dir_,
                              drive_logo,
                              false)));
  drive_in_user_space_->WaitUntilMounted();
#endif
  mount_status_ = true;
}

void UserStorage::UnMountDrive() {
  if (!mount_status_)
    return;
#ifdef WIN32
  std::static_pointer_cast<MaidDriveInUserSpace>(
      drive_in_user_space_)->CleanUp();
#else
  drive_in_user_space_->Unmount();
  drive_in_user_space_->WaitUntilUnMounted();
  boost::system::error_code error_code;
  fs::remove_all(mount_dir_, error_code);
#endif
  mount_status_ = false;
  mount_thread_->join();
}

fs::path UserStorage::mount_dir() {
#ifdef WIN32
  return mount_dir_ / fs::path("/").make_preferred();
#else
  return mount_dir_;
#endif
}

bool UserStorage::mount_status() {
  return mount_status_;
}

bool UserStorage::ParseAndSaveDataMap(const std::string &file_name,
                                      const std::string &serialised_data_map,
                                      std::string *data_map_hash) {
  encrypt::DataMapPtr data_map(ParseSerialisedDataMap(serialised_data_map));
  if (!data_map) {
    DLOG(ERROR) << "Serialised DM doesn't parse.";
    return false;
  }

  *data_map_hash =
      EncodeToBase32(crypto::Hash<crypto::SHA1>(serialised_data_map)) +
      boost::lexical_cast<std::string>(
          GetDurationSinceEpoch().total_microseconds());
  std::string filename_data(PutFilenameData(file_name));
  if (filename_data.empty()) {
    DLOG(ERROR) << "No suitable filename given: " << file_name;
    return false;
  }

  int result(WriteHiddenFile(mount_dir() /
                                 std::string(*data_map_hash +
                                             drive::kMsHidden.string()),
                             filename_data + serialised_data_map,
                             true));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create file: " << result;
    return false;
  }

  return true;
}

int UserStorage::GetDataMap(const fs::path &absolute_path,
                            std::string *serialised_data_map) const {
  return drive_in_user_space_->GetDataMap(
             drive_in_user_space_->RelativePath(absolute_path),
             serialised_data_map);
}

int UserStorage::InsertDataMap(const fs::path &absolute_path,
                               const std::string &serialised_data_map) {
  return drive_in_user_space_->InsertDataMap(
             drive_in_user_space_->RelativePath(absolute_path),
             serialised_data_map);
}

bool UserStorage::SaveShareData(const std::string &serialised_share_data,
                                const std::string &share_id) {
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
  int result(WriteHiddenFile(
                 mount_dir() /
                     drive::kMsShareRoot /
                     std::string(temp_name + drive::kMsHidden.string()),
                 serialised_share_data,
                 true));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create file: " << result;
    return false;
  }
  return true;
}

bool UserStorage::SaveOpenShareData(const std::string &serialised_share_data,
                                    const std::string &share_id) {
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
  int result(WriteHiddenFile(
                 mount_dir() / kSharedStuff /
                     std::string(temp_name + drive::kMsHidden.string()),
                 serialised_share_data,
                 true));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create file: " << result;
    return false;
  }
  return true;
}

int UserStorage::CreateShare(const std::string &sender_public_id,
                             const fs::path &absolute_path,
                             const StringIntMap &contacts,
                             bool private_share,
                             StringIntMap *contacts_results) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  std::string share_id(crypto::Hash<crypto::SHA512>(absolute_path.string()));

  std::vector<pki::SignaturePacketPtr> signature_packets;
  pki::CreateChainedId(&signature_packets, 1);
  asymm::Keys key_ring;
  key_ring.identity = signature_packets[0]->name();
  key_ring.public_key = signature_packets[0]->value();
  key_ring.private_key = signature_packets[0]->private_key();
  key_ring.validation_token = signature_packets[0]->signature();

  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);

  pcs::RemoteChunkStore::ValidationData validation_data(
      PopulateValidationData(key_ring));
  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));
  VoidFunctionOneBool callback(std::bind(&SendContactInfoCallback,
                                         args::_1,
                                         &mutex,
                                         &cond_var,
                                         &results[0]));
  chunk_store_->Store(packet_id,
                      ComposeSignaturePacketValue(*signature_packets[0]),
                      callback,
                      validation_data);
  int result(AwaitingResponse(&mutex, &cond_var, &results));
  if (result != kSuccess) {
    DLOG(ERROR) << "Timed out waiting for the response";
    return result;
  }

  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to store packet.  Packet 1 : " << results[0];
    return results[0];
  }
  std::string directory_id;
  result = drive_in_user_space_->SetShareDetails(
               drive_in_user_space_->RelativePath(absolute_path),
               share_id,
               key_ring,
               sender_public_id,
               private_share,
               &directory_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in creating share of " << absolute_path.string()
                << ", with result of : " << result;
    return result;
  }
  // AddShareUser will send out the informing msg to contacts
  result = AddShareUsers(sender_public_id,
                         absolute_path,
                         contacts,
                         private_share,
                         contacts_results);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to add users to share at " << absolute_path;
    return result;
  }
  return kSuccess;
}

int UserStorage::CreateOpenShare(const std::string &sender_public_id,
                                 const fs::path &absolute_path,
                                 const StringIntMap &contacts,
                                 StringIntMap *contacts_results) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }
  std::string share_id(crypto::Hash<crypto::SHA512>(absolute_path.string()));
  std::vector<pki::SignaturePacketPtr> signature_packets;
  pki::CreateChainedId(&signature_packets, 1);
  asymm::Keys key_ring;
  key_ring.identity = signature_packets[0]->name();
  key_ring.public_key = signature_packets[0]->value();
  key_ring.private_key = signature_packets[0]->private_key();
  key_ring.validation_token = signature_packets[0]->signature();
  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  pcs::RemoteChunkStore::ValidationData validation_data(
      PopulateValidationData(key_ring));
  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));
  VoidFunctionOneBool callback(std::bind(&SendContactInfoCallback,
                                         args::_1,
                                         &mutex,
                                         &cond_var,
                                         &results[0]));
  chunk_store_->Store(packet_id,
                      ComposeSignaturePacketValue(*signature_packets[0]),
                      callback,
                      validation_data);
  int result(AwaitingResponse(&mutex, &cond_var, &results));
  if (result != kSuccess) {
    DLOG(ERROR) << "Timed out waiting for the response";
    return result;
  }
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to store packet.  Packet 1 : " << results[0];
    return results[0];
  }
  std::string directory_id;
  result = drive_in_user_space_->SetShareDetails(
               drive_in_user_space_->RelativePath(absolute_path),
               share_id,
               key_ring,
               sender_public_id,
               false,
               &directory_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in creating share of " << absolute_path.string()
                << ", with result of : " << result;
    return result;
  }
  result = OpenShareInvitation(sender_public_id,
                               absolute_path,
                               contacts,
                               contacts_results);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to invite users to share " << absolute_path;
    return result;
  }
  return kSuccess;
}

int UserStorage::GetAllShares(StringIntMap *shares_names) {
  return drive_in_user_space_->GetAllShares(shares_names);
}

int UserStorage::InsertShare(const fs::path &absolute_path,
                             const std::string &share_id,
                             const std::string &inviter_id,
                             std::string *share_name,
                             const std::string &directory_id,
                             const asymm::Keys &share_keyring) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }
  fs::path share_dir(absolute_path);
  int index(1);
  int result(drive_in_user_space_->InsertShare(
                drive_in_user_space_->RelativePath(share_dir),
                inviter_id,
                directory_id,
                share_id,
                share_keyring));
  while (result == -500317) {  // drive::kInvalidPath
    share_dir = mount_dir() / ((*share_name) + "_" + IntToString(index));
    result = drive_in_user_space_->InsertShare(
                drive_in_user_space_->RelativePath(share_dir),
                inviter_id,
                directory_id,
                share_id,
                share_keyring);
    ++index;
  }
  *share_name = share_dir.filename().string();
  return result;
}

int UserStorage::StopShare(const std::string &sender_public_id,
                           const fs::path &absolute_path) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  std::map<std::string, int> contacts;
  asymm::Keys key_ring;
  std::string share_id;
  maidsafe::drive::DirectoryId directory_id;
  int result(drive_in_user_space_->GetShareDetails(relative_path,
                                                   nullptr,
                                                   &key_ring,
                                                   &share_id,
                                                   nullptr,
                                                   &contacts));
  if (result != kSuccess)
    return result;
  result = drive_in_user_space_->SetShareDetails(relative_path,
                                                 "",
                                                 key_ring,
                                                 sender_public_id,
                                                 drive::kMsPrivateShare,  // value doesn't matter  // NOLINT
                                                 &directory_id);
  if (result != kSuccess)
    return result;

  InformContactsOperation<RemoveShareTag>(sender_public_id,
                                          contacts,
                                          share_id);
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);
  pcs::RemoteChunkStore::ValidationData validation_data(
      PopulateValidationData(key_ring));
  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));

  VoidFunctionOneBool callback(std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  chunk_store_->Delete(packet_id, callback, validation_data);

  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to remove packet. Packet 1 : " << results[0];
    return results[0];
  }

  return kSuccess;
}

int UserStorage::RemoveShare(const fs::path& absolute_path,
                             const std::string &sender_public_id) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  // when own name not provided, this indicates being asked to leave
  // i.e. no notification of leaving to the owner required to be sent
  if (sender_public_id.empty()) {
    return drive_in_user_space_->RemoveShare(
             drive_in_user_space_->RelativePath(absolute_path));
  }

  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  asymm::Keys key_ring;
  std::string share_id;
  std::string owner_id;
  int result(drive_in_user_space_->GetShareDetails(relative_path,
                                                   nullptr,
                                                   nullptr,
                                                   &share_id,
                                                   nullptr,
                                                   nullptr,
                                                   &owner_id));
  if (result != kSuccess)
    return result;
  // Owner doesn't allow to leave (shall use StopShare method)
  if (owner_id == sender_public_id)
    return kOwnerTryingToLeave;

  result = drive_in_user_space_->RemoveShare(
             drive_in_user_space_->RelativePath(absolute_path));
  if (result != kSuccess)
    return result;

  std::map<std::string, int> owner;
  owner.insert(std::make_pair(owner_id , 0));
  return InformContactsOperation<LeaveShareTag>(sender_public_id,
                                                owner,
                                                share_id);
}

void UserStorage::LeaveShare(const std::string &/*sender_public_id*/,
                             const std::string &share_id) {
  fs::path relative_path;
  int result(GetShareDetails(share_id, &relative_path,
                             nullptr, nullptr, nullptr));
  if (result != kSuccess)
    return;

  fs::path share_dir(mount_dir() /
                     drive::kMsShareRoot /
                     relative_path.filename());
  RemoveShare(share_dir);
}

int UserStorage::UpdateShare(const std::string &share_id,
                             const std::string *new_share_id,
                             const std::string *new_directory_id,
                             const asymm::Keys *new_key_ring) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  fs::path relative_path;
  int result(GetShareDetails(share_id, &relative_path,
                             nullptr, nullptr, nullptr));
  if (result != kSuccess)
    return result;

  return drive_in_user_space_->UpdateShare(relative_path,
                                           share_id,
                                           new_share_id,
                                           new_directory_id,
                                           new_key_ring);

//   drive_in_user_space_->RemoveShare(relative_path);
//   return drive_in_user_space_->InsertShare(relative_path, "",
//                 *new_directory_id, *new_share_id, *new_key_ring);
}

int UserStorage::AddShareUsers(const std::string &sender_public_id,
                               const fs::path &absolute_path,
                               const StringIntMap &contacts,
                               bool private_share,
                               StringIntMap *contacts_results) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));

  int result(drive_in_user_space_->AddShareUsers(relative_path,
                                                 contacts,
                                                 private_share));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to add users to share: " << absolute_path.string();
    return result;
  }

  std::string share_id;
  std::string directory_id;
  asymm::Keys key_ring;

  result = drive_in_user_space_->GetShareDetails(relative_path,
                                                 nullptr,
                                                 &key_ring,
                                                 &share_id,
                                                 &directory_id,
                                                 nullptr);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get share details: " << absolute_path.string();
    return result;
  }

  result =
      InformContactsOperation<InsertShareTag>(sender_public_id,
                                              contacts,
                                              share_id,
                                              absolute_path.filename().string(),
                                              directory_id,
                                              key_ring,
                                              "",
                                              contacts_results);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to inform contacts: " << absolute_path.string();
    return result;
  }

  return kSuccess;
}

int UserStorage::AddOpenShareUser(const fs::path &absolute_path,
                                  const StringIntMap &contacts) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }
  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  int result(drive_in_user_space_->AddShareUsers(relative_path,
                                                 contacts,
                                                 false));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to add users to share: " << absolute_path.string();
    return result;
  }
  return kSuccess;
}

int UserStorage::OpenShareInvitation(const std::string &sender_public_id,
                                     const fs::path &absolute_path,
                                     const StringIntMap &contacts,
                                     StringIntMap *contacts_results) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }
  int result(0);
  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path)),
           share_name;
  std::string share_id, directory_id;
  asymm::Keys key_ring;
  result = drive_in_user_space_->GetShareDetails(relative_path,
                                                 &share_name,
                                                 &key_ring,
                                                 &share_id,
                                                 &directory_id,
                                                 nullptr);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get share details: " << absolute_path.string();
    return result;
  }
  result = InformContacts<kOpenShareInvitation>(sender_public_id,
                                                contacts,
                                                share_id,
                                                relative_path,
                                                directory_id,
                                                key_ring,
                                                "",
                                                contacts_results);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to inform contacts: " << absolute_path.string();
    return result;
  }
  return kSuccess;
}

int UserStorage::GetAllShareUsers(
    const fs::path &absolute_path,
    std::map<std::string, int> *all_share_users) const {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  int result(drive_in_user_space_->GetShareDetails(
                 drive_in_user_space_->RelativePath(absolute_path),
                 nullptr,
                 nullptr,
                 nullptr,
                 nullptr,
                 all_share_users));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get share details for " << absolute_path;
    return result;
  }
  return kSuccess;
}

int UserStorage::UserLeavingShare(const std::string &share_id,
                                  const std::string &user_id) {
  std::vector<std::string> user_ids;
  user_ids.push_back(user_id);
  return drive_in_user_space_->RemoveShareUsers(share_id, user_ids);
}

int UserStorage::RemoveShareUsers(const std::string &sender_public_id,
                                  const fs::path &absolute_path,
                                  const std::vector<std::string> &user_ids,
                                  bool private_share) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  std::string share_id;
  asymm::Keys old_key_ring;
  drive_in_user_space_->GetShareDetails(relative_path,
                                        nullptr,
                                        &old_key_ring,
                                        &share_id,
                                        nullptr,
                                        nullptr);
  int result(drive_in_user_space_->RemoveShareUsers(share_id, user_ids));
  if (result != kSuccess)
    return result;

  StringIntMap removed_contacts;
  for (auto it = user_ids.begin(); it != user_ids.end(); ++it) {
    removed_contacts.insert(std::make_pair(*it, kShareReadOnly));
  }
  InformContactsOperation<RemoveShareTag>(sender_public_id,
                                          removed_contacts,
                                          share_id);

  return MovingShare(sender_public_id, share_id,
                     relative_path, old_key_ring, private_share);
}

int UserStorage::MovingShare(const std::string &sender_public_id,
                             const std::string &share_id,
                             const fs::path &relative_path,
                             const asymm::Keys &old_key_ring,
                             bool private_share,
                             std::string *new_share_id_return) {
  std::string new_share_id(RandomString(share_id.size()));
  std::vector<pki::SignaturePacketPtr> signature_packets;
  pki::CreateChainedId(&signature_packets, 1);
  asymm::Keys key_ring;
  key_ring.identity = signature_packets[0]->name();
  key_ring.public_key = signature_packets[0]->value();
  key_ring.private_key = signature_packets[0]->private_key();
  key_ring.validation_token = signature_packets[0]->signature();

  // Store packets
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<int> results;
  results.push_back(kPendingResult);

  pcs::RemoteChunkStore::ValidationData validation_data(
      PopulateValidationData(key_ring));
  std::string packet_id(ComposeSignaturePacketName(key_ring.identity));
  VoidFunctionOneBool callback(std::bind(&SendContactInfoCallback, args::_1,
                                         &mutex, &cond_var, &results[0]));
  chunk_store_->Store(packet_id,
                      ComposeSignaturePacketValue(*signature_packets[0]),
                      callback,
                      validation_data);

  int result(AwaitingResponse(&mutex, &cond_var, &results));
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to store packets.  Packet 1 : " << results[0];
    return results[0];
  }

  std::string directory_id;
  result = drive_in_user_space_->SetShareDetails(relative_path,
                                                 new_share_id,
                                                 key_ring,
                                                 sender_public_id,
                                                 private_share,
                                                 &directory_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in updating share of " << Base32Substr(share_id)
                << ", with result of : " << result;
    return result;
  }

  results.clear();
  results.push_back(kPendingResult);

  validation_data = PopulateValidationData(old_key_ring);
  packet_id = ComposeSignaturePacketName(old_key_ring.identity);
  chunk_store_->Delete(packet_id, callback, validation_data);

  result = AwaitingResponse(&mutex, &cond_var, &results);
  if (result != kSuccess)
    return result;
  if (results[0] != kSuccess) {
    DLOG(ERROR) << "Failed to remove packet.  Packet 1 : " << results[0];
//     return kDeletePacketFailure;
  }

  StringIntMap contacts;
  result = drive_in_user_space_->GetShareDetails(relative_path,
                                                 nullptr,
                                                 nullptr,
                                                 &new_share_id,
                                                 nullptr,
                                                 &contacts);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in getting share deatils of "
                << Base32Substr(share_id) << ", with result of : " << result;
    return result;
  }

  result = InformContactsOperation<UpdateShareTag>(sender_public_id,
                                                   contacts,
                                                   share_id,
                                                   "",
                                                   directory_id,
                                                   key_ring,
                                                   new_share_id);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed in informing contacts in share: "
                << Base32Substr(share_id) << ", with result of : " << result;
    return result;
  }

  if (new_share_id_return)
    *new_share_id_return = new_share_id;

  return kSuccess;
}

int UserStorage::RemoveOpenShareUsers(
    const fs::path &absolute_path,
    const std::vector<std::string> &user_ids) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }
  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  std::string share_id;
  drive_in_user_space_->GetShareDetails(relative_path,
                                        nullptr,
                                        nullptr,
                                        &share_id,
                                        nullptr,
                                        nullptr);
  int result(drive_in_user_space_->RemoveShareUsers(share_id, user_ids));
  if (result != kSuccess)
    return result;
  return kSuccess;
}

int UserStorage::GetShareUsersRights(const fs::path &absolute_path,
                                     const std::string &user_id,
                                     int *admin_rights) const {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  return drive_in_user_space_->GetShareUsersRights(
             drive_in_user_space_->RelativePath(absolute_path),
             user_id,
             admin_rights);
}

int UserStorage::SetShareUsersRights(const std::string &sender_public_id,
                                     const fs::path &absolute_path,
                                     const std::string &user_id,
                                     int admin_rights,
                                     bool private_share) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));
  int old_admin_right;
  int result(drive_in_user_space_->GetShareUsersRights(relative_path,
                                                       user_id,
                                                       &old_admin_right));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed getting access right for contact " << user_id
                << ", with result : " << result;
    return result;
  }

  if (admin_rights == old_admin_right) {
    DLOG(INFO) << "Access right for contact " << user_id
               << ", keeps the same ";
    return kSuccess;
  }

  result = drive_in_user_space_->SetShareUsersRights(relative_path,
                                                     user_id,
                                                     admin_rights);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed setting access right for contact " << user_id
                << ", with result : " << result;
    return result;
  }

  StringIntMap contacts;
  contacts.insert(std::make_pair(user_id, admin_rights));
  asymm::Keys key_ring;
  std::string share_id;
  result = drive_in_user_space_->GetShareDetails(relative_path,
                                                  nullptr,
                                                  &key_ring,
                                                  &share_id,
                                                  nullptr,
                                                  nullptr);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed getting admin right for contact " << user_id
                << ", with result : " << result;
    return result;
  }

  // In case of downgrading : generate new share_id/key and inform all
  // In case of upgrading : just inform the contact of the share key_ring.
  if (old_admin_right > admin_rights) {
    result = MovingShare(sender_public_id, share_id, relative_path,
                         key_ring, private_share, &share_id);
    if (result != kSuccess)
      return result;
  }

  return InformContactsOperation<MemberAccessTag>(sender_public_id,
                                                  contacts,
                                                  share_id,
                                                  "",
                                                  "",
                                                  key_ring);
}

int UserStorage::DowngradeShareUsersRights(
        const std::string &sender_public_id,
        const fs::path &absolute_path,
        const StringIntMap &contacts,
        StringIntMap *results,
        bool private_share) {
  if (!message_handler_) {
    DLOG(WARNING) << "Uninitialised message handler.";
    return kMessageHandlerNotInitialised;
  }

  fs::path relative_path(drive_in_user_space_->RelativePath(absolute_path));

  for (auto it = contacts.begin(); it != contacts.end(); ++it)
    results->insert(std::make_pair((*it).first,
                    drive_in_user_space_->SetShareUsersRights(
                        relative_path,
                        (*it).first,
                        ((*it).second != 0))));

  asymm::Keys old_key_ring;
  std::string share_id;
  drive_in_user_space_->GetShareDetails(relative_path,
                                        nullptr,
                                        &old_key_ring,
                                        &share_id,
                                        nullptr,
                                        nullptr);
  int result(MovingShare(sender_public_id, share_id, relative_path,
                         old_key_ring, private_share, &share_id));
  if (result != kSuccess)
    return result;

  return InformContactsOperation<MemberAccessTag>(sender_public_id,
                                                  contacts,
                                                  share_id,
                                                  "",
                                                  "",
                                                  old_key_ring);
}

int UserStorage::GetShareDetails(const std::string &share_id,
                                 fs::path *relative_path,
                                 asymm::Keys *share_keyring,
                                 std::string *directory_id,
                                 StringIntMap *share_users) {
  return drive_in_user_space_->GetShareDetails(share_id,
                                               relative_path,
                                               share_keyring,
                                               directory_id,
                                               share_users);
}

void UserStorage::MemberAccessChange(
    const std::string &/*my_public_id*/,
    const std::string &/*sender_public_id*/,
    const std::string &share_id,
    int access_right) {
  fs::path relative_path;
  int result(GetShareDetails(share_id, &relative_path,
                             nullptr, nullptr, nullptr));
  if (result != kSuccess)
    return /*result*/;

  asymm::Keys share_keyring;
  if (access_right >= drive::kShareReadWrite) {
    std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
    fs::path hidden_file(mount_dir() /
                         drive::kMsShareRoot /
                         std::string(temp_name + drive::kMsHidden.string()));
    std::string serialised_share_data;
    result = ReadHiddenFile(hidden_file, &serialised_share_data);
    if (result != kSuccess || serialised_share_data.empty()) {
      DLOG(ERROR) << "No such identifier found: " << result;
      return/* result == kSuccess ? kGeneralError : result*/;
    }
    // remove the temp share invitation file no matter insertion succeed or not
    DeleteHiddenFile(hidden_file);

    Message message;
    message.ParseFromString(serialised_share_data);

    if (message.content_size() > 4) {
        share_keyring.identity = message.content(2);
        share_keyring.validation_token = message.content(3);
        asymm::DecodePrivateKey(message.content(4),
                                &(share_keyring.private_key));
        asymm::DecodePublicKey(message.content(5), &(share_keyring.public_key));
    } else {
      DLOG(ERROR) << "Key not received when being upgraded";
      return /*kNoKeyForUpgrade*/;
    }
  }

  /*return */drive_in_user_space_->UpdateShare(relative_path,
                                            share_id,
                                            nullptr,
                                            nullptr,
                                            &share_keyring,
                                            &access_right);
}

int UserStorage::GetPrivateSharesContactBeingOwner(
    const std::string &/*my_public_id*/,
    const std::string &contact_public_id,
    std::vector<std::string> *shares_names) {
  StringIntMap all_shares;
  GetAllShares(&all_shares);
  for (auto it = all_shares.begin(); it != all_shares.end(); ++it) {
    std::string owner_id;
    fs::path share_dir("" / drive::kMsShareRoot / (*it).first);
    drive_in_user_space_->GetShareDetails(share_dir, nullptr, nullptr,
                                          nullptr, nullptr, nullptr,
                                          &owner_id);
    if (owner_id == contact_public_id)
      shares_names->push_back((*it).first);
  }
  return kSuccess;
}

int UserStorage::GetNotes(const fs::path &absolute_path,
                          std::vector<std::string> *notes) const {
  return drive_in_user_space_->GetNotes(
             drive_in_user_space_->RelativePath(absolute_path),
             notes);
}

int UserStorage::AddNote(const fs::path &absolute_path,
                         const std::string &note) {
  return drive_in_user_space_->AddNote(
             drive_in_user_space_->RelativePath(absolute_path),
             note);
}

int UserStorage::ReadHiddenFile(const fs::path &absolute_path,
                                std::string *content) const {
  return drive_in_user_space_->ReadHiddenFile(
             drive_in_user_space_->RelativePath(absolute_path),
             content);
}

int UserStorage::WriteHiddenFile(const fs::path &absolute_path,
                                 const std::string &content,
                                 bool overwrite_existing) {
  return drive_in_user_space_->WriteHiddenFile(
             drive_in_user_space_->RelativePath(absolute_path),
             content,
             overwrite_existing);
}

int UserStorage::DeleteHiddenFile(const fs::path &absolute_path) {
  return drive_in_user_space_->DeleteHiddenFile(
             drive_in_user_space_->RelativePath(absolute_path));
}

int UserStorage::SearchHiddenFiles(const fs::path &absolute_path,
                                   const std::string &regex,
                                   std::list<std::string> *results) {
  return drive_in_user_space_->SearchHiddenFiles(
             drive_in_user_space_->RelativePath(absolute_path),
             regex,
             results);
}

int UserStorage::GetHiddenFileDataMap(
    const boost::filesystem3::path &absolute_path,
    std::string *data_map) {
  return drive_in_user_space_->GetDataMapHidden(
             drive_in_user_space_->RelativePath(absolute_path),
             data_map);
}

bs2::connection UserStorage::ConnectToDriveChanged(
    drive::DriveChangedSlotPtr slot) const {
  return drive_in_user_space_->ConnectToDriveChanged(slot);
}

bs2::connection UserStorage::ConnectToShareChanged(
    drive::ShareChangedSlotPtr slot) const {
  return drive_in_user_space_->ConnectToShareChanged(slot);
}

pcs::RemoteChunkStore::ValidationData UserStorage::PopulateValidationData(
    const asymm::Keys &key_ring) {
  pcs::RemoteChunkStore::ValidationData validation_data;
  validation_data.key_pair = key_ring;
  pca::SignedData signed_data;
  signed_data.set_data(RandomString(64));
  asymm::Sign(signed_data.data(),
              validation_data.key_pair.private_key,
              &validation_data.ownership_proof);
  signed_data.set_signature(validation_data.ownership_proof);
  validation_data.ownership_proof = signed_data.SerializeAsString();
  return validation_data;
}

template<typename Operation>
int UserStorage::InformContactsOperation(
        const std::string &sender_public_id,
        const std::map<std::string, int> &contacts,
        const std::string &share_id,
        const std::string &absolute_path,
        const std::string &directory_id,
        const asymm::Keys &key_ring,
        const std::string &new_share_id,
        StringIntMap *contacts_results) {
  InboxItem admin_message(kShare), non_admin_message(kShare);
  std::string public_key, private_key;

//   admin_message.item_type = kSharedDirectory;
  admin_message.sender_public_id = sender_public_id;
  admin_message.content.push_back(share_id);
//   non_admin_message.item_type = kSharedDirectory;
  non_admin_message.sender_public_id = sender_public_id;
  non_admin_message.content.push_back(share_id);
  AddMessageDetails<Operation>()(absolute_path,
                                 directory_id,
                                 new_share_id,
                                 &admin_message,
                                 &non_admin_message);
  admin_message.content.push_back(key_ring.identity);
  admin_message.content.push_back(key_ring.validation_token);
  asymm::EncodePrivateKey(key_ring.private_key, &private_key);
  admin_message.content.push_back(private_key);
  asymm::EncodePublicKey(key_ring.public_key, &public_key);
  admin_message.content.push_back(public_key);

  int result, aggregate(0);
  if (contacts_results)
    contacts_results->clear();
  for (auto it = contacts.begin(); it != contacts.end(); ++it) {
    // do nothing if trying to send a msg to itself
    if ((*it).first != sender_public_id) {
      if ((*it).second >= kShareReadWrite) {
        admin_message.receiver_public_id = (*it).first;
        result = message_handler_->Send(sender_public_id,
                                        (*it).first,
                                        admin_message);
      } else {
        non_admin_message.receiver_public_id = (*it).first;
        result = message_handler_->Send(sender_public_id,
                                        (*it).first,
                                        non_admin_message);
      }
      if (result != kSuccess) {
        DLOG(ERROR) << "Failed in inform contact " << (*it).first
                    << "  of operation " << ", with result of : "
                    << result;
        ++aggregate;
      }
      if (contacts_results)
        contacts_results->insert(std::make_pair((*it).first, result));
    }
  }

  return aggregate;
}

template<uint32_t ItemType>
int UserStorage::InformContacts(
        const std::string &sender_public_id,
        const std::map<std::string, int> &contacts,
        const std::string &share_id,
        const fs::path &relative_path,  // const std::string &absolute_path
        const std::string &directory_id,
        const asymm::Keys &key_ring,
        const std::string& /*new_share_id*/,
        StringIntMap *contacts_results) {
  InboxItemType item_type(static_cast<InboxItemType>(ItemType));
  InboxItem message(item_type);
  std::string public_key, private_key;
  message.sender_public_id = sender_public_id;
  message.content.push_back(share_id);
  switch (ItemType) {
    case kOpenShareInvitation:
      // fs::path(absolute_path).filename().string());
      message.content.push_back(relative_path.string());
      message.content.push_back(directory_id);
      break;
    default:
      DLOG(ERROR) << "Unknown constant";
  }
  message.content.push_back(key_ring.identity);
  message.content.push_back(key_ring.validation_token);
  asymm::EncodePrivateKey(key_ring.private_key, &private_key);
  message.content.push_back(private_key);
  asymm::EncodePublicKey(key_ring.public_key, &public_key);
  message.content.push_back(public_key);

  int result, aggregate(0);
  if (contacts_results)
    contacts_results->clear();
  for (auto it = contacts.begin(); it != contacts.end(); ++it) {
    if (it->first != sender_public_id) {
      message.receiver_public_id = it->first;
      result = message_handler_->Send(sender_public_id,
                                      it->first,
                                      message);
      if (result != kSuccess) {
        DLOG(ERROR) << "Failed in inform contact " << it->first
                    << " of operation " << ItemType << ", with result "
                    << result;
        ++aggregate;
      }
      if (contacts_results)
        contacts_results->insert(std::make_pair(it->first, result));
    }
  }
  return aggregate;
}

std::string UserStorage::ConstructFile(const std::string &serialised_data_map) {
  encrypt::DataMapPtr data_map(ParseSerialisedDataMap(serialised_data_map));
  if (!data_map) {
    DLOG(ERROR) << "Data map didn't parse.";
    return "";
  }

  uint32_t file_size(data_map->chunks.empty() ?
      static_cast<uint32_t>(data_map->content.size()) : 0);
  auto it(data_map->chunks.begin());
  while (it != data_map->chunks.end()) {
    if (kFileRecontructionLimit < (file_size + (*it).size)) {
      DLOG(ERROR) << "File too large to read.";
      return "";
    }
    file_size += (*it).size;
    ++it;
  }

  // TODO(Team): decide based on the size whether to go ahead.
  // Update: It's now only possible to read a file up to uint32_t size.
  // if (file_size > 'some limit')
  //   return "";

  encrypt::SelfEncryptor self_encryptor(data_map, chunk_store_);
  std::unique_ptr<char[]> contents(new char[file_size]);
  self_encryptor.Read(contents.get(), file_size, 0);
  std::string file_content(contents.get(), file_size);

  return file_content;
}

}  // namespace lifestuff

}  // namespace maidsafe
