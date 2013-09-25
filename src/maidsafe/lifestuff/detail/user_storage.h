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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_

#include "boost/regex.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#ifdef WIN32
#ifdef HAVE_CBFS
#include "maidsafe/drive/win_drive.h"
#else
#include "maidsafe/drive/dummy_win_drive.h"
#endif
#else
#include "maidsafe/drive/unix_drive.h"
#endif

#include "maidsafe/data_store/sure_file_store.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"
#include "maidsafe/lifestuff/detail/data_atlas.pb.h"

namespace maidsafe {
namespace lifestuff {

const NonEmptyString kDriveLogo("Lifestuff Drive");
const boost::filesystem::path kLifeStuffConfigPath("LifeStuff-Config");

#ifdef WIN32
#ifdef HAVE_CBFS
template <typename Storage>
struct Drive {
  typedef drive::CbfsDriveInUserSpace<Storage> MaidDrive;
};
#else
typedef drive::DummyWinDriveInUserSpace MaidDrive;
#endif
#else
template <typename Storage>
struct Drive {
  typedef drive::FuseDriveInUserSpace<Storage> MaidDrive;
};
#endif

class UserStorage {
 public:

  typedef nfs_client::MaidNodeNfs Storage;
  typedef std::shared_ptr<Storage> StoragePtr;
  typedef Drive<Storage>::MaidDrive Drive;
  typedef passport::Maid Maid;

  explicit UserStorage();
  ~UserStorage() {}

  void MountDrive(StoragePtr storage, Session& session, OnServiceAddedFunction on_service_added);
  void UnMountDrive();

  boost::filesystem::path mount_path();
  boost::filesystem::path owner_path();
  bool mount_status();

 private:
  UserStorage& operator=(const UserStorage&);
  UserStorage(const UserStorage&);

  bool ReadConfigFile(const fs::path& absolute_path, std::string* content);
  bool WriteConfigFile(const fs::path& absolute_path, const NonEmptyString& content,
                       bool overwrite_existing);

  bool mount_status_;
  boost::filesystem::path mount_path_;
  std::unique_ptr<Drive> drive_;
  std::thread mount_thread_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
