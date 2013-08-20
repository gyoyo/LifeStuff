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
template<typename Storage>
struct Drive {
typedef drive::FuseDriveInUserSpace<Storage> MaidDrive;
};
#endif

class UserStorage {
 public:

  typedef data_store::SureFileStore Storage;  // TODO() change to lifestuff's storage type.
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

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
