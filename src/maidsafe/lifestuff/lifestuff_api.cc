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

#include "maidsafe/lifestuff/lifestuff_api.h"

#include "maidsafe/lifestuff/client_impl.h"

namespace maidsafe {
namespace lifestuff {

LifeStuff::LifeStuff(const Slots& slots)
  : client_impl_(new ClientImpl<Product::kLifeStuff>(slots)) {}

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

void LifeStuff::LogIn(ReportProgressFunction& report_progress) {
  return client_impl_->LogIn(report_progress);
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
