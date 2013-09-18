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

#include "maidsafe/lifestuff/lifestuff_api.h"

#include "maidsafe/lifestuff/client_impl.h"

namespace maidsafe {
namespace lifestuff {

struct ClientData {
  typedef int Storage;
  std::unique_ptr<Keyword> keyword_, confirmation_keyword_;
  std::unique_ptr<Pin> pin_, confirmation_pin_;
  std::unique_ptr<Password> password_, confirmation_password_, current_password_;
  ClientMpid client_mpid_;
};

LifeStuff::LifeStuff(const Slots& slots)
  : client_impl_(new ClientImpl<ClientData>(slots)) {}

LifeStuff::~LifeStuff() {}

void LifeStuff::InsertUserInput(uint32_t position, const std::string& characters, InputField input_field) {
  return client_impl_->InsertUserInput(position, characters, input_field);
}

void LifeStuff::RemoveUserInput(uint32_t position, uint32_t length, InputField input_field) {
  return client_impl_->RemoveUserInput(position, length, input_field);
}

void LifeStuff::ClearUserInput(InputField input_field) {
  return client_impl_->ClearUserInput(input_field);
}

bool LifeStuff::ConfirmUserInput(InputField input_field) {
  return client_impl_->ConfirmUserInput(input_field);
}

void LifeStuff::CreateUser(const std::string& storage_path, ReportProgressFunction& report_progress) {
  return client_impl_->CreateUser(storage_path, report_progress);
}

void LifeStuff::LogIn(const std::string& storage_path, ReportProgressFunction& report_progress) {
  return client_impl_->LogIn(storage_path, report_progress);
}

void LifeStuff::LogOut() {
  return client_impl_->LogOut();
}

void LifeStuff::MountDrive() {
  return client_impl_->MountDrive();
}

void LifeStuff::UnMountDrive() {
  return client_impl_->UnMountDrive();
}

void LifeStuff::ChangeKeyword(ReportProgressFunction& report_progress) {
  return client_impl_->ChangeKeyword(report_progress);
}

void LifeStuff::ChangePin(ReportProgressFunction& report_progress) {
  return client_impl_->ChangePin(report_progress);
}

void LifeStuff::ChangePassword(ReportProgressFunction& report_progress) {
  return client_impl_->ChangePassword(report_progress);
}

bool LifeStuff::logged_in() const {
  return client_impl_->logged_in();
}

std::string LifeStuff::mount_path() {
  return client_impl_->mount_path().string();
}

std::string LifeStuff::owner_path() {
  return client_impl_->owner_path().string();
}

}  // namespace lifestuff
}  // namespace maidsafe
