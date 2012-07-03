/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Functional tests for Client Controller operations
* Version:      1.0
* Created:      2009-01-29-02.29.46
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

#include <list>
#include <string>
#include <vector>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;


namespace maidsafe {

namespace lifestuff {

namespace test {

class UserCredentialsTest : public testing::Test {
 public:
  UserCredentialsTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session_(),
        session2_(),
        asio_service_(10),
        asio_service2_(10),
#ifndef LOCAL_TARGETS_ONLY
        node_(),
        node2_(),
#endif
        remote_chunk_store_(),
        remote_chunk_store2_(),
        user_credentials_(),
        user_credentials2_(),
        keyword_(RandomAlphaNumericString(8)),
        pin_(CreatePin()),
        password_(RandomAlphaNumericString(8)) {}

 protected:
  void SetUp() {
    asio_service_.Start();
    asio_service2_.Start();
#ifdef LOCAL_TARGETS_ONLY
  remote_chunk_store_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                        *test_dir_ / "simulation",
                                        asio_service_.service());
#else
  remote_chunk_store_ = BuildChunkStore(*test_dir_, &node_);
#endif
    user_credentials_.reset(new UserCredentials(*remote_chunk_store_,
                                                session_,
                                                asio_service_.service()));
  }

  void TearDown() {
    asio_service_.Stop();
    asio_service2_.Stop();
  }

  void CreateSecondUserCredentials() {
#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store2_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service2_.service());
#else
    remote_chunk_store2_ = BuildChunkStore(*test_dir_, &node2_);
#endif
    user_credentials2_.reset(new UserCredentials(*remote_chunk_store2_,
                                                 session2_,
                                                 asio_service2_.service()));
  }

  std::shared_ptr<fs::path> test_dir_;
  Session session_, session2_;
  AsioService asio_service_, asio_service2_;
#ifndef LOCAL_TARGETS_ONLY
  std::shared_ptr<pd::Node> node_, node2_;
#endif
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_, remote_chunk_store2_;
  std::shared_ptr<UserCredentials> user_credentials_, user_credentials2_;
  std::string keyword_, pin_, password_;

 private:
  UserCredentialsTest(const UserCredentialsTest&);
  UserCredentialsTest &operator=(const UserCredentialsTest&);
};

TEST_F(UserCredentialsTest, FUNC_LoginSequence) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  ASSERT_EQ(kUserDoesntExist, user_credentials_->LogIn(keyword_, pin_, password_));
  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  ASSERT_EQ(keyword_, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "User created.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Logged out.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(keyword_, pin_, password_));
  ASSERT_EQ(keyword_, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "Logged in.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Logged out.\n===================\n";

  ASSERT_NE(kSuccess, user_credentials_->LogIn(RandomAlphaNumericString(9), pin_, password_));
  LOG(kInfo) << "Can't log in with fake details.";
}

TEST_F(UserCredentialsTest, FUNC_ChangeDetails) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  ASSERT_EQ(kUserDoesntExist, user_credentials_->LogIn(keyword_, pin_, password_));
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  ASSERT_EQ(keyword_, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "User created.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Logged out.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(keyword_, pin_, password_));
  ASSERT_EQ(keyword_, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());

  LOG(kInfo) << "Logged in.\n===================\n";
  const std::string kNewKeyword(RandomAlphaNumericString(9));
  ASSERT_EQ(kSuccess, user_credentials_->ChangeKeyword(kNewKeyword));
  ASSERT_EQ(kNewKeyword, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "Changed keyword.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Logged out.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(kNewKeyword, pin_, password_));
  ASSERT_EQ(kNewKeyword, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "Logged in.\n===================\n";

  const std::string kNewPin(CreatePin());
  ASSERT_EQ(kSuccess, user_credentials_->ChangePin(kNewPin));
  ASSERT_EQ(kNewKeyword, session_.keyword());
  ASSERT_EQ(kNewPin, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "Changed pin.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Logged out.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(kNewKeyword, kNewPin, password_));
  ASSERT_EQ(kNewKeyword, session_.keyword());
  ASSERT_EQ(kNewPin, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "Logged in.\n===================\n";

  const std::string kNewPassword(RandomAlphaNumericString(9));
  ASSERT_EQ(kSuccess, user_credentials_->ChangePassword(kNewPassword));
  ASSERT_EQ(kNewKeyword, session_.keyword());
  ASSERT_EQ(kNewPin, session_.pin());
  ASSERT_EQ(kNewPassword, session_.password());
  LOG(kInfo) << "Changed password.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Logged out.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(kNewKeyword, kNewPin, kNewPassword));
  ASSERT_EQ(kNewKeyword, session_.keyword());
  ASSERT_EQ(kNewPin, session_.pin());
  ASSERT_EQ(kNewPassword, session_.password());
  LOG(kInfo) << "Logged in. New u/p/w.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Logged out.\n===================\n";

  ASSERT_EQ(kUserDoesntExist, user_credentials_->LogIn(keyword_, pin_, password_));
  ASSERT_EQ(kUserDoesntExist, user_credentials_->LogIn(kNewKeyword, pin_, password_));
  ASSERT_EQ(kAccountCorrupted, user_credentials_->LogIn(kNewKeyword, kNewPin, password_));
  ASSERT_EQ(kUserDoesntExist, user_credentials_->LogIn(kNewKeyword, pin_, kNewPassword));
  ASSERT_EQ(kUserDoesntExist, user_credentials_->LogIn(keyword_, kNewPin, kNewPassword));
  LOG(kInfo) << "Can't log in with old u/p/w.";
}

TEST_F(UserCredentialsTest, DISABLED_FUNC_ParallelLogin) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  ASSERT_EQ(kUserDoesntExist, user_credentials_->LogIn(keyword_, pin_, password_));
  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  ASSERT_EQ(keyword_, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "User created.\n===================\n";

  CreateSecondUserCredentials();
  ASSERT_EQ(kSuccess, user_credentials2_->LogIn(keyword_, pin_, password_));
  LOG(kInfo) << "Successful parallel log in.";
}

TEST_F(UserCredentialsTest, FUNC_MultiUserCredentialsLoginAndLogout) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  ASSERT_EQ(kUserDoesntExist, user_credentials_->LogIn(keyword_, pin_, password_));
  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  ASSERT_EQ(keyword_, session_.keyword());
  ASSERT_EQ(pin_, session_.pin());
  ASSERT_EQ(password_, session_.password());
  LOG(kInfo) << "User created.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Logged out.\n===================\n";

  CreateSecondUserCredentials();
  ASSERT_EQ(kSuccess, user_credentials2_->LogIn(keyword_, pin_, password_));
  LOG(kInfo) << "Successful parallel log in.";
  ASSERT_EQ(kSuccess, user_credentials2_->Logout());
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Logged out.\n===================\n";
}

TEST_F(UserCredentialsTest, FUNC_UserCredentialsDeletion) {
  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  passport::Passport& pass(session_.passport());
  std::string anmid_name(pass.SignaturePacketDetails(passport::kAnmid, true).identity),
              ansmid_name(pass.SignaturePacketDetails(passport::kAnsmid, true).identity),
              antmid_name(pass.SignaturePacketDetails(passport::kAntmid, true).identity),
              anmaid_name(pass.SignaturePacketDetails(passport::kAnmaid, true).identity),
              maid_name(pass.SignaturePacketDetails(passport::kMaid, true).identity),
              pmid_name(pass.SignaturePacketDetails(passport::kPmid, true).identity),
              mid_name(pass.IdentityPacketName(passport::kMid, true)),
              smid_name(pass.IdentityPacketName(passport::kSmid, true)),
              tmid_name(pass.IdentityPacketName(passport::kTmid, true)),
              stmid_name(pass.IdentityPacketName(passport::kStmid, true));
  ASSERT_EQ(kSuccess, user_credentials_->DeleteUserCredentials());
  ASSERT_EQ("", remote_chunk_store_->Get(anmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(ansmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(antmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(anmaid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(maid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(pmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(mid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(smid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(tmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(stmid_name));

  ASSERT_NE(kSuccess, user_credentials_->Logout());
  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  ASSERT_EQ(kSuccess, user_credentials_->LogIn(keyword_, pin_, password_));

  anmid_name = pass.SignaturePacketDetails(passport::kAnmid, true).identity;
  ansmid_name = pass.SignaturePacketDetails(passport::kAnsmid, true).identity;
  antmid_name = pass.SignaturePacketDetails(passport::kAntmid, true).identity;
  anmaid_name = pass.SignaturePacketDetails(passport::kAnmaid, true).identity;
  maid_name = pass.SignaturePacketDetails(passport::kMaid, true).identity;
  pmid_name = pass.SignaturePacketDetails(passport::kPmid, true).identity;
  mid_name = pass.IdentityPacketName(passport::kMid, true);
  smid_name = pass.IdentityPacketName(passport::kSmid, true);
  tmid_name = pass.IdentityPacketName(passport::kTmid, true);
  stmid_name = pass.IdentityPacketName(passport::kStmid, true);

  ASSERT_EQ(kSuccess, user_credentials_->DeleteUserCredentials());
  ASSERT_EQ("", remote_chunk_store_->Get(anmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(ansmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(antmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(anmaid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(maid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(pmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(mid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(smid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(tmid_name));
  ASSERT_EQ("", remote_chunk_store_->Get(stmid_name));

  ASSERT_NE(kSuccess, user_credentials_->Logout());
  ASSERT_NE(kSuccess, user_credentials_->LogIn(keyword_, pin_, password_));
}

TEST_F(UserCredentialsTest, DISABLED_FUNC_SessionSaverTimer) {
  ASSERT_TRUE(session_.keyword().empty());
  ASSERT_TRUE(session_.pin().empty());
  ASSERT_TRUE(session_.password().empty());
  LOG(kInfo) << "Preconditions fulfilled.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->CreateUser(keyword_, pin_, password_));
  LOG(kInfo) << "Created user.\n===================\n";
  Sleep(bptime::seconds(3));
  LOG(kInfo) << "Slept 3.\n===================\n";
  ASSERT_EQ(kSuccess, session_.AddPublicId(RandomAlphaNumericString(5)));
  LOG(kInfo) << "Modified session.\n===================\n";
  Sleep(bptime::seconds(/*kSecondsInterval * 12*/5));
  LOG(kInfo) << "Slept 3.\n===================\n";
  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  LOG(kInfo) << "Logout.\n===================\n";
  Sleep(bptime::seconds(5));
  LOG(kInfo) << "Slept 5.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(keyword_, pin_, password_));
  LOG(kInfo) << "Log in.\n===================\n";
  Sleep(bptime::seconds(3));
  LOG(kInfo) << "Slept 3.\n===================\n";
  ASSERT_EQ(kSuccess, session_.AddPublicId(RandomAlphaNumericString(5)));
  LOG(kInfo) << "Modified session.\n===================\n";
  Sleep(bptime::seconds(/*kSecondsInterval * 12*/5));
  LOG(kInfo) << "Slept 3.\n===================\n";
  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  LOG(kInfo) << "Logout.\n===================\n";
  Sleep(bptime::seconds(5));
  LOG(kInfo) << "Slept 5.\n===================\n";

  ASSERT_EQ(kSuccess, user_credentials_->LogIn(keyword_, pin_, password_));
  LOG(kInfo) << "Log in.\n===================\n";
  ASSERT_EQ(kSuccess, user_credentials_->Logout());
  LOG(kInfo) << "Logout.\n===================\n";
  Sleep(bptime::seconds(5));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
