/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/lifestuff_api.h"

namespace maidsafe {
namespace lifestuff {
namespace test {

class UserInputTest : public testing::Test {
 public:
  typedef std::unique_ptr<LifeStuff> LifeStuffPtr;

  enum InvalidInputField { kInvalidInputField = 7 };

  UserInputTest()
    : lifestuff_() {}

 protected:
  void SetUp() {
    Slots slots;
    UpdateAvailableFunction update_available([](const std::string&) {});
    NetworkHealthFunction network_health([](int32_t) {});
    OperationsPendingFunction operations_pending([](bool) {});
    slots.update_available = update_available;
    slots.network_health = network_health;
    slots.operations_pending = operations_pending;
    lifestuff_.reset(new LifeStuff(slots));
  }

  void TearDown() {}

  LifeStuffPtr lifestuff_;
};

TEST_F(UserInputTest, BEH_ValidKeyword) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "k", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "e", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "y", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "w", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "o", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "r", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "d", kKeyword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kKeyword));
}

TEST_F(UserInputTest, BEH_ValidPin) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "0", kPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "1", kPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "2", kPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "3", kPin));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPin));
}

TEST_F(UserInputTest, BEH_ValidPassword) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "p", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "a", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "w", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "o", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "r", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(7, "d", kPassword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPassword));
}

TEST_F(UserInputTest, BEH_ValidConfirmationKeyword) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "k", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "e", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "y", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "w", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "o", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "r", kKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "d", kKeyword));

  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "d", kConfirmationKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "r", kConfirmationKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "o", kConfirmationKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "w", kConfirmationKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "y", kConfirmationKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "e", kConfirmationKeyword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "k", kConfirmationKeyword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kConfirmationKeyword));
}

TEST_F(UserInputTest, BEH_ValidConfirmationPin) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "0", kPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "1", kPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "2", kPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "3", kPin));

  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "3", kConfirmationPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "2", kConfirmationPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "1", kConfirmationPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "0", kConfirmationPin));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kConfirmationPin));
}

TEST_F(UserInputTest, BEH_ValidConfirmationPassword) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "p", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "a", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "w", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "o", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "r", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(7, "d", kPassword));

  EXPECT_NO_THROW(lifestuff_->InsertUserInput(7, "d", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "r", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "o", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "w", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "s", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "s", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "a", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "p", kConfirmationPassword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kConfirmationPassword));
}

TEST_F(UserInputTest, BEH_PasswordClearRedo) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "p", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "a", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "w", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "o", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "r", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(7, "d", kPassword));

  EXPECT_NO_THROW(lifestuff_->ClearUserInput(kPassword));

  EXPECT_NO_THROW(lifestuff_->InsertUserInput(7, "d", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "r", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "o", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "w", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "a", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "p", kPassword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPassword));
}

TEST_F(UserInputTest, BEH_PasswordInsertRemove) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "p", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "a", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "w", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "o", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "r", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(7, "d", kPassword));

  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(7, 1, kPassword));
  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(6, 1, kPassword));
  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(5, 1, kPassword));
  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(4, 1, kPassword));
  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(3, 1, kPassword));
  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(2, 1, kPassword));
  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(1, 1, kPassword));
  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(0, 1, kPassword));

  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kPassword));

  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "p", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "a", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "w", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "o", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "r", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(7, "d", kPassword));

  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPassword));
}

TEST_F(UserInputTest, BEH_InvalidKeyword) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "k", kKeyword));
  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(0, 1, kKeyword));
  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kKeyword));
}

TEST_F(UserInputTest, BEH_InvalidPin) {
  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kPin));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "1", kPin));
  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPin));
  EXPECT_NO_THROW(lifestuff_->RemoveUserInput(0, 1, kPin));
  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kPin));
}

TEST_F(UserInputTest, BEH_InvalidConfirmationPassword) {
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "p", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "a", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "s", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "w", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "o", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "r", kPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(7, "d", kPassword));

  EXPECT_NO_THROW(lifestuff_->InsertUserInput(7, "d", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(6, "r", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(5, "o", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(4, "w", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "s", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "s", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "a", kConfirmationPassword));
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "q", kConfirmationPassword));

  EXPECT_FALSE(lifestuff_->ConfirmUserInput(kConfirmationPassword));
}

TEST_F(UserInputTest, BEH_InvalidInputField) {
  EXPECT_THROW(lifestuff_->InsertUserInput(0, "p", InputField(kInvalidInputField)), common_error);
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(0, "a", kPassword));
  EXPECT_THROW(lifestuff_->InsertUserInput(1, "s", InputField(kInvalidInputField)), common_error);
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(1, "s", kPassword));
  EXPECT_THROW(lifestuff_->InsertUserInput(2, "w", InputField(kInvalidInputField)), common_error);
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(2, "o", kPassword));
  EXPECT_THROW(lifestuff_->InsertUserInput(3, "r", InputField(kInvalidInputField)), common_error);
  EXPECT_NO_THROW(lifestuff_->InsertUserInput(3, "d", kPassword));

  EXPECT_THROW(lifestuff_->ConfirmUserInput(InputField(kInvalidInputField)), common_error);
  EXPECT_TRUE(lifestuff_->ConfirmUserInput(kPassword));
}

}  // namespace test
}  // namespace lifestuff
}  // namespace maidsafe
