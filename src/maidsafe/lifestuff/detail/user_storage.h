/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_

#include "boost/regex.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#ifdef WIN32
#  ifdef HAVE_CBFS
#    include "maidsafe/drive/win_drive.h"
#  else
#    include "maidsafe/drive/dummy_win_drive.h"
#  endif
#else
#  include "maidsafe/drive/unix_drive.h"
#endif
#include "maidsafe/drive/return_codes.h"

#include "maidsafe/data_store/surefile_store.h"

#include "maidsafe/nfs/nfs.h"
#include "maidsafe/nfs/client_utils.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"
#include "maidsafe/lifestuff/detail/data_atlas.pb.h"


namespace maidsafe {
namespace lifestuff {

const NonEmptyString kDriveLogo("Lifestuff Drive");
const boost::filesystem::path kLifeStuffConfigPath("LifeStuff-Config");

#ifdef WIN32
#  ifdef HAVE_CBFS
template<typename Storage>
struct Drive {
  typedef drive::CbfsDriveInUserSpace<Storage> MaidDrive;
};
#  else
typedef drive::DummyWinDriveInUserSpace MaidDrive;
#  endif
#else
typedef drive::FuseDriveInUserSpace MaidDrive;
#endif

template<typename Storage>
class UserStorage {
 public:
  typedef typename Drive<Storage>::MaidDrive Drive;
  typedef passport::Maid Maid;

  explicit UserStorage();
  ~UserStorage() {}

  void MountDrive(Storage& storage, Session& session);
  void UnMountDrive(Session& session);

  boost::filesystem::path mount_path();
  boost::filesystem::path owner_path();
  bool mount_status();

 private:
  UserStorage &operator=(const UserStorage&);
  UserStorage(const UserStorage&);

  bool ReadConfigFile(const fs::path& absolute_path, std::string* content);
  bool WriteConfigFile(const fs::path& absolute_path,
                       const NonEmptyString& content,
                       bool overwrite_existing);

  bool mount_status_;
  boost::filesystem::path mount_path_;
  std::unique_ptr<Drive> drive_;
  std::thread mount_thread_;
};

// Implementation
// --------------

template<typename Storage>
UserStorage<Storage>::UserStorage()
    : mount_status_(false),
      mount_path_(),
      drive_(),
      mount_thread_() {}

template<typename Storage>
void UserStorage<Storage>::MountDrive(Storage& storage, Session& session) {
  if (mount_status_)
    return;
#ifdef WIN32
  std::uint32_t drive_letters, mask = 0x4, count = 2;
  drive_letters = GetLogicalDrives();
  while ((drive_letters & mask) != 0) {
    mask <<= 1;
    ++count;
  }
  if (count > 25) {
    LOG(kError) << "No available drive letters.";
    return;
  }
  char drive_name[3] = {'A' + static_cast<char>(count), ':', '\0'};
  mount_path_ = drive_name;
  drive_.reset(new Drive(storage,
                         session.passport().Get<Maid>(true),
                         session.unique_user_id(),
                         session.root_parent_id(),
                         mount_path_,
                         kDriveLogo.string(),
                         session.max_space(),
                         session.used_space()));
  mount_status_ = true;
  if (session.root_parent_id() != drive_->root_parent_id())
    session.set_root_parent_id(drive_->root_parent_id());
#else
  boost::system::error_code error_code;
  if (!boost::filesystem::exists(mount_path_)) {
    boost::filesystem::create_directories(mount_path_, error_code);
    if (error_code) {
      LOG(kError) << "Failed to create mount dir(" << mount_path_ << "): "
                  << error_code.message();
    }
  }
  drive_.reset(new MaidDrive(storage,
                             session.passport().Get<Maid>(true),
                             session.unique_user_id(),
                             session.root_parent_id(),
                             mount_path_,
                             kDriveLogo.string(),
                             session.max_space(),
                             session.used_space()));
  mount_thread_ = std::move(std::thread([this] {
                                          drive_->Mount();
                                        }));
  mount_status_ = drive_->WaitUntilMounted();
#endif
}

template<typename Storage>
void UserStorage<Storage>::UnMountDrive(Session& session) {
  if (!mount_status_)
    return;
  int64_t max_space(0), used_space(0);
#ifdef WIN32
  drive_->Unmount(max_space, used_space);
#else
  drive_->Unmount(max_space, used_space);
  drive_->WaitUntilUnMounted();
  mount_thread_.join();
  boost::system::error_code error_code;
  boost::filesystem::remove_all(mount_path_, error_code);
#endif
  mount_status_ = false;
  session.set_max_space(max_space);
  session.set_used_space(used_space);
}

template<typename Storage>
boost::filesystem::path UserStorage<Storage>::mount_path() {
#ifdef WIN32
  return mount_path_ / boost::filesystem::path("/").make_preferred();
#else
  return mount_path_;
#endif
}

template<typename Storage>
boost::filesystem::path UserStorage<Storage>::owner_path() {
  return mount_path() / kOwner;
}

template<typename Storage>
bool UserStorage<Storage>::mount_status() {
  return mount_status_;
}

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
