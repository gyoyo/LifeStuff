/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Unit tests for Authentication
* Version:      1.0
* Created:      2009-01-29-03.19.59
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/buffered_chunk_store.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

//#include "maidsafe/pd/client/client_container.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/utils.h"
#include "maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

class AuthenticationTest : public testing::Test {
 public:
  AuthenticationTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session_(new Session),
//        client_container_(),
        remote_chunk_store_(),
        authentication_(session_),
        username_(RandomAlphaNumericString(8)),
        pin_("1234"),
        password_(RandomAlphaNumericString(8)),
        ser_dm_(RandomString(1000)),
        surrogate_ser_dm_(RandomString(1000)),
        converter_(new YeOldeSignalToCallbackConverter),
        asio_service_() {}

 protected:
  void SetUp() {
    asio_service_.Start(10);

//    if (GetParam() == "Local Storage") {
    remote_chunk_store_ = pcs::CreateLocalChunkStore(*test_dir_,
                                                     asio_service_.service());
//    } else if (GetParam() == "Network Storage") {
//      client_container_ = SetUpClientContainer(*test_dir_);
//      ASSERT_TRUE(client_container_.get() != nullptr);
//      remote_chunk_store_.reset(new pd::RemoteChunkStore(
//          client_container_->chunk_store(),
//          client_container_->chunk_manager(),
//          client_container_->chunk_action_authority()));
//    } else {
//      FAIL() << "Invalid test value parameter";
//    }

    session_->ResetSession();
    remote_chunk_store_->sig_chunk_stored()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Stored, converter_.get(),
                  args::_1, args::_2));
    remote_chunk_store_->sig_chunk_deleted()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Deleted, converter_.get(),
                  args::_1, args::_2));
    remote_chunk_store_->sig_chunk_modified()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Modified, converter_.get(),
                  args::_1, args::_2));
    authentication_.Init(remote_chunk_store_, converter_);
  }

  void TearDown() {
    asio_service_.Stop();
  }

  std::string PacketValueFromSession(passport::PacketType packet_type,
                                     bool confirmed) {
    return session_->passport_->PacketName(packet_type, confirmed);
  }

  std::string PacketSignerFromSession(passport::PacketType packet_type,
                                      bool confirmed) {
    switch (packet_type) {
      case passport::kMid:
          return session_->passport_->PacketName(passport::kAnmid, confirmed);
      case passport::kSmid:
          return session_->passport_->PacketName(passport::kAnsmid, confirmed);
      case passport::kTmid:
      case passport::kStmid:
          return session_->passport_->PacketName(passport::kAntmid, confirmed);
      default: return "";
    }
  }

  void SetPassword(const std::string &password) {
    session_->set_password(password);
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session_;
//  ClientContainerPtr client_container_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
  Authentication authentication_;
  std::string username_, pin_, password_, ser_dm_, surrogate_ser_dm_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter_;
  AsioService asio_service_;

 private:
  AuthenticationTest(const AuthenticationTest&);
  AuthenticationTest &operator=(const AuthenticationTest&);
};

TEST_F(AuthenticationTest, FUNC_CreateUserSysPackets) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
}

TEST_F(AuthenticationTest, FUNC_GoodLogin) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  std::string ser_dm_login, ser_dm_login1;
  authentication_.GetMasterDataMap(password_, &ser_dm_login, &ser_dm_login1);
  ASSERT_EQ(ser_dm_, ser_dm_login);
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  SetPassword(password_);

  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_ + "1"));

  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));

  ser_dm_login.clear();
  ser_dm_login1.clear();
  authentication_.GetMasterDataMap(password_, &ser_dm_login, &ser_dm_login1);
  ASSERT_EQ(ser_dm_ + "1", ser_dm_login);
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
}

TEST_F(AuthenticationTest, FUNC_LoginNoUser) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  std::string ser_dm_login, ser_dm_login1;
  password_ += "password_tonto";
  authentication_.GetMasterDataMap(password_, &ser_dm_login, &ser_dm_login1);
  ASSERT_NE(ser_dm_, ser_dm_login);
}

TEST_F(AuthenticationTest, FUNC_RegisterUserOnce) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
}

TEST_F(AuthenticationTest, FUNC_RegisterUserWithoutNetworkCheck) {
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));
  ASSERT_EQ(username_, session_->username());
  ASSERT_EQ(pin_, session_->pin());
  ASSERT_EQ(password_, session_->password());
}

TEST_F(AuthenticationTest, FUNC_RegisterUserTwice) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));
  session_->ResetSession();
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
}

TEST_F(AuthenticationTest, FUNC_RepeatedSaveSessionBlocking) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));
  std::string original_tmidname(PacketValueFromSession(passport::kTmid, true));
  ASSERT_FALSE(original_tmidname.empty());

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  ser_dm_ = RandomString(1000);
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));

  ser_dm_ = RandomString(1000);
  ASSERT_EQ(kSuccess, authentication_.SaveSession(ser_dm_));
  std::string tmidname(PacketValueFromSession(passport::kTmid, true));
  std::string stmidname(PacketValueFromSession(passport::kStmid, true));

//  ASSERT_TRUE(packet_manager_->KeyUnique(
//                  pca::ApplyTypeToName(original_tmidname,
//                                       pca::kModifiableByOwner),
//                  PacketSignerFromSession(passport::kTmid, true)));
//  ASSERT_FALSE(packet_manager_->KeyUnique(
//                   pca::ApplyTypeToName(stmidname,
//                                        pca::kModifiableByOwner),
//                   PacketSignerFromSession(passport::kStmid, true)));
//  ASSERT_FALSE(packet_manager_->KeyUnique(
//                   pca::ApplyTypeToName(tmidname,
//                                        pca::kModifiableByOwner),
//                   PacketSignerFromSession(passport::kTmid, true)));
}

TEST_F(AuthenticationTest, FUNC_ChangeUsername) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));

  std::string original_tmidname(PacketValueFromSession(passport::kTmid, true));
  std::string original_stmidname(PacketValueFromSession(passport::kStmid,
                                                        true));
  ASSERT_FALSE(original_tmidname.empty());
  ASSERT_FALSE(original_stmidname.empty());

  const std::string kNewName(RandomAlphaNumericString(9));
  ASSERT_EQ(kSuccess, authentication_.ChangeUsername(ser_dm_ + "2", kNewName));
  ASSERT_EQ(kNewName, session_->username());

  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(kNewName, pin_));
  std::string ser_dm_login, ser_dm_login1;
  authentication_.GetMasterDataMap(password_, &ser_dm_login, &ser_dm_login1);
  ASSERT_EQ(ser_dm_ + "2", ser_dm_login);
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
//  ASSERT_TRUE(packet_manager_->KeyUnique(
//                  pca::ApplyTypeToName(original_stmidname,
//                                       pca::kModifiableByOwner),
//                  PacketSignerFromSession(passport::kTmid, true)));
}

TEST_F(AuthenticationTest, FUNC_ChangePin) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));

  std::string original_tmidname(PacketValueFromSession(passport::kTmid, true));
  std::string original_stmidname(PacketValueFromSession(passport::kStmid,
                                                        true));
  ASSERT_FALSE(original_tmidname.empty());
  ASSERT_FALSE(original_stmidname.empty());

  const std::string kNewPin("7894");
  ASSERT_EQ(kSuccess, authentication_.ChangePin(ser_dm_ + "2", kNewPin));
  ASSERT_EQ(kNewPin, session_->pin());

  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, kNewPin));
  std::string ser_dm_login, ser_dm_login1;
  authentication_.GetMasterDataMap(password_, &ser_dm_login, &ser_dm_login1);
  ASSERT_EQ(ser_dm_ + "2", ser_dm_login);
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
}

TEST_F(AuthenticationTest, FUNC_ChangePassword) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));

  const std::string kNewPassword(RandomAlphaNumericString(9));
  ASSERT_EQ(kSuccess, authentication_.ChangePassword(ser_dm_ + "2",
                                                     kNewPassword));
  ASSERT_EQ(kNewPassword, session_->password());

  std::string ser_dm_login, ser_dm_login1;
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  authentication_.GetMasterDataMap(password_, &ser_dm_login, &ser_dm_login1);
  ASSERT_NE(ser_dm_, ser_dm_login);

  ser_dm_login.clear();
  ser_dm_login1.clear();
  ASSERT_EQ(kUserExists, authentication_.GetUserInfo(username_, pin_));
  authentication_.GetMasterDataMap(kNewPassword, &ser_dm_login, &ser_dm_login1);
  ASSERT_NE(ser_dm_, ser_dm_login);
}

TEST_F(AuthenticationTest, FUNC_RegisterLeaveRegister) {
  ASSERT_EQ(kUserDoesntExist, authentication_.GetUserInfo(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));

  //  Remove user.
  ASSERT_EQ(kSuccess, authentication_.RemoveMe());

  //  Check user no longer registered.
  session_->ResetSession();
  ASSERT_NE(kUserExists, authentication_.GetUserInfo(username_, pin_));

  session_->ResetSession();
  ASSERT_EQ(kSuccess, authentication_.CreateUserSysPackets(username_, pin_));
  ASSERT_EQ(kSuccess, authentication_.CreateTmidPacket(password_,
                                                       ser_dm_,
                                                       surrogate_ser_dm_));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
