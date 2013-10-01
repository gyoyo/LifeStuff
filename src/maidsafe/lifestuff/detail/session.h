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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_

#include <mutex>
#include <map>
#include <string>
#include <set>
#include <utility>
#include <vector>

#include "maidsafe/common/utils.h"

#include "maidsafe/passport/passport.h"
#include "maidsafe/passport/detail/secure_string.h"

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {
namespace lifestuff {

namespace test {
class SessionTest;
}

typedef passport::detail::Keyword Keyword;
typedef passport::detail::Pin Pin;
typedef passport::detail::Password Password;

class Session {
 public:
  typedef passport::Passport Passport;
  typedef std::pair<std::string, uint16_t> Endpoint;

  Session();
  explicit Session(const NonEmptyString& serialised_data_atlas);

  ~Session();

  Passport& passport();

  NonEmptyString session_name() const;
  Identity unique_user_id() const;
  Identity drive_root_id() const;
  boost::filesystem::path storage_path() const;
  int64_t max_space() const;
  int64_t used_space() const;
  bool initialised();
  const Keyword& keyword() const;
  const Pin& pin() const;
  const Password& password() const;

  void set_session_name();
  void set_unique_user_id(const Identity& unique_user_id);
  void set_drive_root_id(const Identity& drive_root_id);
  void set_storage_path(const boost::filesystem::path& storage_path);
  void set_max_space(const int64_t& max_space);
  void set_used_space(const int64_t& used_space);
  void set_initialised();
  void set_keyword(const Keyword& keyword);
  void set_pin(const Pin& pin);
  void set_password(const Password& password);
  void set_keyword_pin_password(const Keyword& keyword, const Pin& pin, const Password& password);

  void set_bootstrap_endpoints(const std::vector<Endpoint>& bootstrap_endpoints);
  std::vector<Endpoint> bootstrap_endpoints() const;

  NonEmptyString Serialise();

  friend class test::SessionTest;

 private:
  Session& operator=(const Session&);
  Session(const Session&);

  struct UserDetails {
    UserDetails()
        : unique_user_id(),
          drive_root_id(),
          storage_path(),
          max_space(1073741824),
          used_space(0),
          session_name(HexEncode(crypto::SHA1Hash(RandomAlphaNumericString(20)))) {}
    Identity unique_user_id;
    Identity drive_root_id;
    boost::filesystem::path storage_path;
    int64_t max_space;
    int64_t used_space;
    NonEmptyString session_name;
  };

  std::unique_ptr<Passport> passport_;
  std::vector<Endpoint> bootstrap_endpoints_;
  UserDetails user_details_;
  bool initialised_;
  std::unique_ptr<Keyword> keyword_;
  std::unique_ptr<Pin> pin_;
  std::unique_ptr<Password> password_;

  // probably need a modified bool here since used_space varies.
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_SESSION_H_
