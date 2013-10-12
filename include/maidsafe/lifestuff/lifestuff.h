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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_H_

#include <cstdint>
#include <string>
#include <functional>

namespace maidsafe {
namespace lifestuff {

// Type passed to user input functions in LifeStuff class to determine which variable(s) to
// process.
enum InputField {
  kPin = 0,
  kKeyword,
  kPassword,
  kConfirmationPin,
  kConfirmationKeyword,
  kConfirmationPassword,
  kCurrentPassword
};

// Used in conjunction with ProgressCode to report execution state during various function calls
// via the ReportProgressFunction function, see definition below.
enum Action {
  kCreateUser = 0,
  kLogin,
  kChangeKeyword,
  kChangePin,
  kChangePassword
};
// See above discussion for Action.
enum ProgressCode {
  kInitialiseProcess = 0,
  kCreatingUserCredentials,
  kJoiningNetwork,
  kInitialisingClientComponents,
  kCreatingVault,
  kStartingVault,
  kVerifyingMount,
  kVerifyingUnmount,
  kStoringUserCredentials,
  kRetrievingUserCredentials,
  kConfirmingUserInput
};

// New version update.
typedef std::function<void(const std::string&)> UpdateAvailableFunction;
// Network health.
typedef std::function<void(int32_t)> NetworkHealthFunction;
// Safe to quit.
typedef std::function<void(bool)> OperationsPendingFunction;  // NOLINT Brian
// Config file parsing error.
typedef std::function<void()> ConfigurationErrorFunction;
// Associate storage location with drive directory.
typedef std::function<void()> OnServiceAddedFunction;

// Slots are used to provide useful information back to the client application.
struct Slots {
  UpdateAvailableFunction update_available;
  NetworkHealthFunction network_health;
  OperationsPendingFunction operations_pending;
  ConfigurationErrorFunction configuration_error;
  OnServiceAddedFunction on_service_added;
};

// Some methods may take some time to complete, e.g. Login. The ReportProgressFunction is used to
// relay back to the client application the current execution state.
typedef std::function<void(Action, ProgressCode)> ReportProgressFunction;

// Some internally used constants.
const std::string kAppHomeDirectory(".lifestuff");
const std::string kOwner("Owner");
const char kCharRegex[] = ".*";
const char kDigitRegex[] = "\\d";

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
