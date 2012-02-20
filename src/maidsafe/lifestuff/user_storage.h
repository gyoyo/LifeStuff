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

#ifndef MAIDSAFE_LIFESTUFF_USER_STORAGE_H_
#define MAIDSAFE_LIFESTUFF_USER_STORAGE_H_

#include <map>
#include <string>
#include <vector>
#include "boost/filesystem.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#ifdef WIN32
#  include "maidsafe/drive/win_drive.h"
#else
#  include "maidsafe/drive/unix_drive.h"
#endif

#include "maidsafe/common/alternative_store.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"

#include "maidsafe/pki/packet.h"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 201
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

#ifdef WIN32
  typedef maidsafe::drive::CbfsDriveInUserSpace MaidDriveInUserSpace;
#else
  typedef maidsafe::drive::FuseDriveInUserSpace MaidDriveInUserSpace;
#endif

namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace pd { class RemoteChunkStore; }

namespace lifestuff {

class MessageHandler;
class Session;
class YeOldeSignalToCallbackConverter;

class UserStorage {
 public:
  explicit UserStorage(
              std::shared_ptr<pd::RemoteChunkStore> chunk_store,
              std::shared_ptr<YeOldeSignalToCallbackConverter> converter);
  virtual ~UserStorage() {}

  virtual void MountDrive(const fs::path &mount_dir_path,
                          const std::string &session_name,
                          std::shared_ptr<Session> session,
                          bool creation,
                          const std::string &drive_logo = "LifeStuff Drive");
  virtual void UnMountDrive();
  virtual fs::path g_mount_dir();
  virtual bool mount_status();

  void SetMessageHandler(std::shared_ptr<MessageHandler> message_handler);

  // ********************* File / Folder Transfers *****************************
  int GetDataMap(const fs::path &absolute_path,
                 std::string *serialised_data_map) const;
  int InsertDataMap(const fs::path &absolute_path,
                    const std::string &serialised_data_map);
  int GetDirectoryListing(const fs::path &absolute_path,
                          std::string *parent_id,
                          std::string *directory_id) const;
  int InsertDirectoryListing(const fs::path &absolute_path,
                             const std::string &parent_id,
                             const std::string &directory_id);

  // ****************************** Shares *************************************
  int CreateShare(const fs::path &absolute_path,
                  const std::map<std::string, bool> &contacts,
                  std::string *share_id_result = nullptr);
  int InsertShare(const std::string &share_id,
                  const fs::path &absolute_path,
                  const std::string &directory_id,
                  const asymm::Keys &share_keyring);
  int StopShare(const std::string &share_id);
  int LeaveShare(const std::string & share_id);
  int ModifyShareDetails(const std::string &share_id,
                         const std::string *new_share_id,
                         const std::string *new_directory_id,
                         const asymm::Keys *new_key_ring);
  int AddShareUsers(const std::string &share_id,
                    const std::map<std::string, bool> &contacts);
  void GetAllShareUsers(const std::string &share_id,
                        std::map<std::string, bool> *all_share_users) const;
  int RemoveShareUsers(const std::string &share_id,
                       const std::vector<std::string> &user_ids);
  int GetShareUsersRights(const std::string &share_id,
                          const std::string &user_id,
                          bool *admin_rights) const;
  int SetShareUsersRights(const std::string &share_id,
                          const std::string &user_id,
                          bool admin_rights);

  // **************************** File Notes ***********************************
  int GetNotes(const fs::path &absolute_path,
               std::vector<std::string> *notes) const;
  int AddNote(const fs::path &absolute_path, const std::string &note);

  // *************************** Hidden Files **********************************
  int ReadHiddenFile(const fs::path &absolute_path, std::string *content) const;
  int WriteHiddenFile(const fs::path &absolute_path,
                      const std::string &content,
                      bool overwrite_existing);
  int DeleteHiddenFile(const fs::path &absolute_path);
  int SearchHiddenFiles(const fs::path &relative_path,
                        const std::string &regex,
                        std::list<std::string> *results);

  void NewMessageSlot(const pca::Message &message);
  // ************************* Signals Handling ********************************
  bs2::connection ConnectToDriveChanged(drive::DriveChangedSlotPtr slot) const;
  bs2::connection ConnectToShareChanged(drive::ShareChangedSlotPtr slot) const;

 private:
  void InformContactsOperation(
      const std::map<std::string, bool> &contacts,
      const ShareOperations operation,
      const std::string &share_id,
      const std::string &absolute_path = "",
      const std::string &directory_id = "",
      const asymm::Keys &key_ring = asymm::Keys(),
      const std::string &new_share_id = "");
  AlternativeStore::ValidationData PopulateValidationData(
      const asymm::Keys &key_ring);

  bool mount_status_;
  std::shared_ptr<pd::RemoteChunkStore> chunk_store_;
  std::shared_ptr<MaidDriveInUserSpace> drive_in_user_space_;
  std::shared_ptr<Session> session_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter_;
  std::shared_ptr<MessageHandler> message_handler_;
  fs::path g_mount_dir_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_USER_STORAGE_H_
