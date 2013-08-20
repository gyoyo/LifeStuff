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

#include "maidsafe/lifestuff/detail/user_storage.h"

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/utils.h"


namespace maidsafe {
namespace lifestuff {

UserStorage::UserStorage()
    : mount_status_(false),
      mount_path_(),
      drive_(),
      mount_thread_() {}

void UserStorage::MountDrive(Storage& storage, Session& session) {
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
  drive_.reset(new     Drive(storage,
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

void UserStorage::UnMountDrive(Session& session) {
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

boost::filesystem::path UserStorage::mount_path() {
#ifdef WIN32
  return mount_path_ / boost::filesystem::path("/").make_preferred();
#else
  return mount_path_;
#endif
}

boost::filesystem::path UserStorage::owner_path() {
  return mount_path() / kOwner;
}

bool UserStorage::mount_status() {
  return mount_status_;
}

}  // namespace lifestuff
}  // namespace maidsafe
