/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/lifestuff/detail/user_storage.h"

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/utils.h"

namespace maidsafe {
namespace lifestuff {

UserStorage::UserStorage() : mount_status_(false), mount_path_(), drive_(), mount_thread_() {}

void UserStorage::MountDrive(StoragePtr storage, Session& session,
                             OnServiceAddedFunction on_service_added) {
  if (mount_status_)
    return;
  drive::OnServiceAdded service_added = [on_service_added]() { on_service_added(); };
  std::string product_id;
#ifdef WIN32
  mount_path_ = drive::GetNextAvailableDrivePath();
  product_id = BOOST_PP_STRINGIZE(CBFS_APPLICATION_KEY);
  drive_.reset(new Drive(storage, session.unique_user_id(), session.drive_root_id(), mount_path_,
                         product_id, kDriveLogo.string(), service_added));
  mount_status_ = true;
  if (session.drive_root_id() != drive_->drive_root_id())
    session.set_drive_root_id(drive_->drive_root_id());
#else
  boost::system::error_code error_code;
  if (!boost::filesystem::exists(mount_path_)) {
    boost::filesystem::create_directories(mount_path_, error_code);
    if (error_code) {
      LOG(kError) << "Failed to create mount dir(" << mount_path_ << "): " << error_code.message();
    }
  }
  drive_.reset(new Drive(storage, session.passport().Get<Maid>(true), session.unique_user_id(),
                         session.drive_root_id(), mount_path_, kDriveLogo.string(),
                         session.max_space(), session.used_space()));
  mount_thread_ = std::move(std::thread([this] { drive_->Mount(); }));
  mount_status_ = drive_->WaitUntilMounted();
#endif
}

void UserStorage::UnMountDrive() {
  if (!mount_status_)
    return;
  drive_->Unmount();
#ifndef WIN32
  drive_->WaitUntilUnMounted();
  mount_thread_.join();
  boost::system::error_code error_code;
  boost::filesystem::remove_all(mount_path_, error_code);
#endif
  mount_status_ = false;
}

boost::filesystem::path UserStorage::mount_path() {
#ifdef WIN32
  return mount_path_ / boost::filesystem::path("/").make_preferred();
#else
  return mount_path_;
#endif
}

boost::filesystem::path UserStorage::owner_path() { return mount_path() / kOwner; }

bool UserStorage::mount_status() { return mount_status_; }

}  // namespace lifestuff
}  // namespace maidsafe
