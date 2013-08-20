/* Copyright 2013 MaidSafe.net limited

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

#include "maidsafe/lifestuff/client_impl.h"

namespace maidsafe {
namespace lifestuff {

ClientImpl::ClientImpl(const Slots& slots)
  : logged_in_(false),
    keyword_(),
    confirmation_keyword_(),
    pin_(),
    confirmation_pin_(),
    password_(),
    confirmation_password_(),
    current_password_(),
    session_(),
    client_maid_(session_, slots),
    client_mpid_() {}

ClientImpl::~ClientImpl() {}

void ClientImpl::InsertUserInput(uint32_t position, const std::string& characters, InputField input_field) {
  switch (input_field) {
    case kKeyword: {
      return detail::InsertUserInput<Keyword>()(keyword_, position, characters);
    }
    case kPin: {
      return detail::InsertUserInput<Pin>()(pin_, position, characters);
    }
    case kPassword: {
      return detail::InsertUserInput<Password>()(password_, position, characters);
    }
    case kConfirmationKeyword: {
      return detail::InsertUserInput<Keyword>()(confirmation_keyword_, position, characters);
    }
    case kConfirmationPin: {
      return detail::InsertUserInput<Pin>()(confirmation_pin_, position, characters);
    }
    case kConfirmationPassword: {
      return detail::InsertUserInput<Password>()(confirmation_password_, position, characters);
    }
    case kCurrentPassword: {
      return detail::InsertUserInput<Password>()(current_password_, position, characters);
    }
    default:
      ThrowError(CommonErrors::unknown);
  }
  return;
}

void ClientImpl::RemoveUserInput(uint32_t position, uint32_t length, InputField input_field) {
  switch (input_field) {
    case kKeyword: {
      return detail::RemoveUserInput<Keyword>()(keyword_, position, length);
    }
    case kPin: {
      return detail::RemoveUserInput<Pin>()(pin_, position, length);
    }
    case kPassword: {
      return detail::RemoveUserInput<Password>()(password_, position, length);
    }
    case kConfirmationKeyword: {
      return detail::RemoveUserInput<Keyword>()(confirmation_keyword_, position, length);
    }
    case kConfirmationPin: {
      return detail::RemoveUserInput<Pin>()(confirmation_pin_, position, length);
    }
    case kConfirmationPassword: {
      return detail::RemoveUserInput<Password>()(confirmation_password_, position, length);
    }
    case kCurrentPassword: {
      return detail::RemoveUserInput<Password>()(current_password_, position, length);
    }
    default:
      ThrowError(CommonErrors::unknown);
  }
  return;
}

void ClientImpl::ClearUserInput(InputField input_field) {
  switch (input_field) {
    case kKeyword: {
      return detail::ClearUserInput<Keyword>()(keyword_);
    }
    case kPin: {
      return detail::ClearUserInput<Pin>()(pin_);
    }
    case kPassword: {
      return detail::ClearUserInput<Password>()(password_);
    }
    case kConfirmationKeyword: {
      return detail::ClearUserInput<Keyword>()(confirmation_keyword_);
    }
    case kConfirmationPin: {
      return detail::ClearUserInput<Pin>()(confirmation_pin_);
    }
    case kConfirmationPassword: {
      return detail::ClearUserInput<Password>()(confirmation_password_);
    }
    case kCurrentPassword: {
      return detail::ClearUserInput<Password>()(current_password_);
    }
    default:
      ThrowError(CommonErrors::unknown);
  }
  return;
}

bool ClientImpl::ConfirmUserInput(InputField input_field) {
  switch (input_field) {
    case kKeyword: {
      return detail::ConfirmUserInput<Keyword>()(keyword_);
    }
    case kPin: {
      return detail::ConfirmUserInput<Pin>()(pin_);
    }
    case kPassword: {
      return detail::ConfirmUserInput<Password>()(password_);
    }
    case kConfirmationKeyword: {
      return detail::ConfirmUserInput<Keyword>()(keyword_, confirmation_keyword_);
    }
    case kConfirmationPin: {
      return detail::ConfirmUserInput<Pin>()(pin_, confirmation_pin_);
    }
    case kConfirmationPassword: {
      return detail::ConfirmUserInput<Password>()(password_, confirmation_password_);
    }
    case kCurrentPassword: {
      return detail::ConfirmUserInput<Password>()(password_, confirmation_password_, current_password_, session_);
    }
    default:
      ThrowError(CommonErrors::unknown);
  }
  return false;
}

void ClientImpl::CreateUser(const boost::filesystem::path& storage_path,
                                     ReportProgressFunction& report_progress) {
  FinaliseUserInput();
  ResetConfirmationInput();
  client_maid_.CreateUser(*keyword_, *pin_, *password_, storage_path, report_progress);
  ResetInput();
  logged_in_ = true;
  return;
}

void ClientImpl::LogIn(const boost::filesystem::path& storage_path,
                                ReportProgressFunction& report_progress) {
  FinaliseUserInput();
  client_maid_.LogIn(*keyword_, *pin_, *password_, storage_path, report_progress);
  ResetInput();
  logged_in_ = true;
  return;
}

void ClientImpl::LogOut() {
  client_maid_.LogOut();
}

void ClientImpl::MountDrive() {
  client_maid_.MountDrive();
}

void ClientImpl::UnMountDrive() {
  client_maid_.UnMountDrive();
}

void ClientImpl::ChangeKeyword(ReportProgressFunction& report_progress) {
  report_progress(kChangeKeyword, kConfirmingUserInput);
  if (!ConfirmUserInput(kCurrentPassword))
    ThrowError(CommonErrors::invalid_parameter);
  client_maid_.ChangeKeyword(session_.keyword(),
                             *keyword_,
                             session_.pin(),
                             session_.password(),
                             report_progress);
  keyword_.reset();
  confirmation_keyword_.reset();
  current_password_.reset();
  return;
}

void ClientImpl::ChangePin(ReportProgressFunction& report_progress) {
  report_progress(kChangePin, kConfirmingUserInput);
  if (!ConfirmUserInput(kCurrentPassword))
    ThrowError(CommonErrors::invalid_parameter);
  client_maid_.ChangePin(session_.keyword(),
                         session_.pin(),
                         *pin_,
                         session_.password(),
                         report_progress);
  pin_.reset();
  confirmation_pin_.reset();
  current_password_.reset();
  return;
}

void ClientImpl::ChangePassword(ReportProgressFunction& report_progress) {
  report_progress(kChangePassword, kConfirmingUserInput);
  if (!ConfirmUserInput(kCurrentPassword))
    ThrowError(CommonErrors::invalid_parameter);
  client_maid_.ChangePassword(session_.keyword(), session_.pin(), *password_, report_progress);
  password_.reset();
  confirmation_password_.reset();
  current_password_.reset();
  return;
}

bool ClientImpl::logged_in() const {
  return logged_in_;
}

boost::filesystem::path ClientImpl::mount_path() {
  return client_maid_.mount_path();
}

boost::filesystem::path ClientImpl::owner_path() {
  return client_maid_.owner_path();
}

void ClientImpl::FinaliseUserInput() {
  keyword_->Finalise();
  pin_->Finalise();
  password_->Finalise();
  return;
}

void ClientImpl::ResetInput() {
  keyword_.reset();
  pin_.reset();
  password_.reset();
}

void ClientImpl::ResetConfirmationInput() {
  confirmation_keyword_.reset();
  confirmation_pin_.reset();
  confirmation_password_.reset();
}

}  // namespace lifestuff
}  // namespace maidsafe
