/*  Copyright 2013 MaidSafe.net limited

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

#include "maidsafe/lifestuff/detail/session.h"

#include <memory>
#include <vector>
#include <limits>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/detail/data_atlas.pb.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace maidsafe {
namespace lifestuff {

Session::Session()
    : passport_(new Passport),
      bootstrap_endpoints_(),
      user_details_(),
      initialised_(false),
      keyword_(),
      pin_(),
      password_() {}

Session::Session(const NonEmptyString& serialised_data_atlas) {
  DataAtlas data_atlas;
  data_atlas.ParseFromString(serialised_data_atlas.string());

  if (data_atlas.user_data().unique_user_id().empty()) {
    LOG(kError) << "Unique user ID is empty.";
    return;
  }

  set_unique_user_id(Identity(data_atlas.user_data().unique_user_id()));
  set_drive_root_id(Identity(data_atlas.user_data().drive_root_id()));
  set_storage_path(data_atlas.user_data().storage_path());
  set_max_space(data_atlas.user_data().max_space());
  set_used_space(data_atlas.user_data().used_space());

  passport_.reset(new Passport(NonEmptyString(data_atlas.passport_data().serialised_passport())));
}

Session::~Session() {}

Session::Passport& Session::passport() { return *passport_; }

NonEmptyString Session::session_name() const { return user_details_.session_name; }

Identity Session::unique_user_id() const { return user_details_.unique_user_id; }

Identity Session::drive_root_id() const { return user_details_.drive_root_id; }

boost::filesystem::path Session::storage_path() const { return user_details_.storage_path; }

int64_t Session::max_space() const { return user_details_.max_space; }

int64_t Session::used_space() const { return user_details_.used_space; }

bool Session::initialised() { return initialised_; }

const Keyword& Session::keyword() const { return *keyword_; }

const Pin& Session::pin() const { return *pin_; }

const Password& Session::password() const { return *password_; }

void Session::set_session_name() {
  NonEmptyString random(RandomAlphaNumericString(64));
  user_details_.session_name = NonEmptyString(HexEncode(crypto::Hash<crypto::SHA1>(random)));
}

void Session::set_unique_user_id(const Identity& unique_user_id) {
  user_details_.unique_user_id = unique_user_id;
}

void Session::set_drive_root_id(const Identity& drive_root_id) {
  user_details_.drive_root_id = drive_root_id;
}

void Session::set_storage_path(const boost::filesystem::path& vault_path) {
  user_details_.storage_path = vault_path;
}

void Session::set_max_space(const int64_t& max_space) { user_details_.max_space = max_space; }

void Session::set_used_space(const int64_t& used_space) { user_details_.used_space = used_space; }

void Session::set_initialised() { initialised_ = true; }

void Session::set_keyword(const Keyword& keyword) {
  keyword_.reset(new Keyword(keyword.string()));
  return;
}

void Session::set_pin(const Pin& pin) {
  pin_.reset(new Pin(pin.string()));
  return;
}

void Session::set_password(const Password& password) {
  password_.reset(new Password(password.string()));
  return;
}

void Session::set_keyword_pin_password(const Keyword& keyword, const Pin& pin,
                                       const Password& password) {
  set_keyword(keyword);
  set_pin(pin);
  set_password(password);
  return;
}

void Session::set_bootstrap_endpoints(const std::vector<Endpoint>& bootstrap_endpoints) {
  bootstrap_endpoints_ = bootstrap_endpoints;
}

std::vector<std::pair<std::string, uint16_t>> Session::bootstrap_endpoints() const {
  return bootstrap_endpoints_;
}

NonEmptyString Session::Serialise() {
  DataAtlas data_atlas;

  UserData* user_data(data_atlas.mutable_user_data());
  user_data->set_unique_user_id(unique_user_id().string());
  user_data->set_drive_root_id(drive_root_id().string());
  user_data->set_storage_path(storage_path().string());
  user_data->set_max_space(max_space());
  user_data->set_used_space(used_space());

  data_atlas.set_timestamp(
      boost::lexical_cast<std::string>(GetDurationSinceEpoch().total_microseconds()));

  NonEmptyString serialised_passport(passport_->Serialise());
  PassportData* passport_data(data_atlas.mutable_passport_data());
  passport_data->set_serialised_passport(serialised_passport.string());

  return NonEmptyString(data_atlas.SerializeAsString());
}

}  // namespace lifestuff
}  // namespace maidsafe
