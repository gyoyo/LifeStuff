/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
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

#include "maidsafe/lifestuff/detail/public_id.h"

#include "boost/thread/thread.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace args = std::placeholders;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

typedef std::map<std::string, ContactStatus> ContactMap;

class PublicIdTest : public testing::TestWithParam<std::string> {
 public:
  PublicIdTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session1_(new Session),
        session2_(new Session),
        remote_chunk_store1_(),
        remote_chunk_store2_(),
        public_id1_(),
        public_id2_(),
        asio_service1_(),
        asio_service2_(),
        public_identity1_("User 1 " + RandomAlphaNumericString(8)),
        public_identity2_("User 2 " + RandomAlphaNumericString(8)),
        received_public_identity_(),
#ifndef LOCAL_TARGETS_ONLY
        client_container1_(),
        client_container2_(),
#endif
        interval_(3) {}

  void ManyContactsSlot(const std::string&, const std::string&, volatile bool *done, int *count) {
    ++(*count);
    if (*count == 5)
      *done = true;
  }

  void NewContactSlot(const std::string&,
                      const std::string &other_public_id,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_identity_ = other_public_id;
    cond_var->notify_one();
  }

  bool ReceivedPublicUsernameEmpty(bool* ignore) {
    if (*ignore == true) {
      *ignore = false;
      return false;
    }
    return received_public_identity_.empty();
  }

  void NewContactCounterSlot(const std::string&,
                             const std::string &other_public_id,
                             const int &times,
                             int *counter,
                             boost::mutex* mutex,
                             boost::condition_variable* cond_var) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_identity_ = other_public_id;
    ++(*counter);
    if (*counter == times)
      cond_var->notify_one();
  }

  void ContactRequestSlot(const std::string&,
                          const std::string &other_public_id,
                          boost::mutex* mutex,
                          boost::condition_variable *cond_var) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_identity_ = other_public_id;
    cond_var->notify_one();
  }

  void ContactConfirmedSlot(const std::string&,
                            const std::string &signal_public_id,
                            std::string *slot_public_id,
                            boost::mutex* mutex,
                            boost::condition_variable* cond_var) {
    boost::mutex::scoped_lock lock(*mutex);
    *slot_public_id  = signal_public_id;
    cond_var->notify_one();
  }

 protected:
  void SetUp() {
    session1_->Reset();
    session2_->Reset();
    asio_service1_.Start(10);
    asio_service2_.Start(10);

#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store1_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service1_.service());
    remote_chunk_store2_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service2_.service());
#else
    remote_chunk_store1_ = BuildChunkStore(*test_dir_, &client_container1_);
    remote_chunk_store2_ = BuildChunkStore(*test_dir_, &client_container2_);
#endif

    public_id1_.reset(new PublicId(remote_chunk_store1_, session1_, asio_service1_.service()));

    public_id2_.reset(new PublicId(remote_chunk_store2_, session2_, asio_service2_.service()));
  }

  void TearDown() {
    public_id1_->StopCheckingForNewContacts();
    public_id2_->StopCheckingForNewContacts();
#ifndef LOCAL_TARGETS_ONLY
    client_container1_->Stop(nullptr);
    client_container2_->Stop(nullptr);
#endif
    asio_service1_.Stop();
    asio_service2_.Stop();
    remote_chunk_store1_->WaitForCompletion();
    remote_chunk_store2_->WaitForCompletion();
  }

  void CreateTestSignaturePackets(std::shared_ptr<Session> session) {
    ASSERT_EQ(kSuccess, session->passport().CreateSigningPackets());
    ASSERT_EQ(kSuccess, session->passport().ConfirmSigningPackets());
  }

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<Session> session1_, session2_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store1_,
                                         remote_chunk_store2_;
  std::shared_ptr<PublicId> public_id1_, public_id2_;

  AsioService asio_service1_, asio_service2_;

  std::string public_identity1_, public_identity2_, received_public_identity_;
#ifndef LOCAL_TARGETS_ONLY
  ClientContainerPtr client_container1_, client_container2_;
#endif
  bptime::seconds interval_;

 private:
  explicit PublicIdTest(const PublicIdTest&);
  PublicIdTest &operator=(const PublicIdTest&);
};

TEST_F(PublicIdTest, FUNC_CreateInvalidId) {
  ASSERT_EQ(kPublicIdEmpty, public_id1_->CreatePublicId("", false));
  ASSERT_EQ(kPublicIdEmpty, public_id1_->CreatePublicId("", true));

  ASSERT_EQ(kNoPublicIds, public_id1_->StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, false));

  ASSERT_EQ(kStorePublicIdFailure, public_id1_->CreatePublicId(public_identity1_, false));

  ASSERT_EQ(kStorePublicIdFailure, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kStorePublicIdFailure, public_id2_->CreatePublicId(public_identity1_, false));
  ASSERT_EQ(kStorePublicIdFailure, public_id2_->CreatePublicId(public_identity1_, true));
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdAntiSocial) {
  // Create user1 who doesn't accept new contacts, and user2 who does
  boost::mutex mutex;
  boost::condition_variable cond_var;
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, false));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  public_id1_->ConnectToNewContactSignal(std::bind(&PublicIdTest::NewContactSlot, this,
                                                   args::_1, args::_2, &mutex, &cond_var));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  ASSERT_EQ(kSendContactInfoFailure, public_id2_->SendContactInfo(public_identity2_,
                                                                  public_identity1_));

  {
    bool ignore(true);
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock,
                                    interval_ * 2,
                                    std::bind(&PublicIdTest::ReceivedPublicUsernameEmpty,
                                              this, &ignore)));
  }
  ASSERT_TRUE(received_public_identity_.empty());
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdSociable) {
  boost::mutex mutex;
  boost::condition_variable cond_var;
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Connect a slot which will reject the new contact
  bs2::connection connection(public_id1_->ConnectToNewContactSignal(
                                 std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2,
                                           &mutex, &cond_var)));
  ASSERT_EQ(kSuccess, public_id2_->SendContactInfo(public_identity2_, public_identity1_));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  ASSERT_EQ(public_identity2_, received_public_identity_);
  Contact received_contact;
  ASSERT_EQ(kSuccess, session1_->contact_handler_map()[public_identity1_]->ContactInfo(
                          received_public_identity_,
                          &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);

  received_contact = Contact();
  std::string public_id3(public_identity2_ + "1");
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_id3, true));
  ASSERT_EQ(kSuccess, public_id2_->SendContactInfo(public_id3, public_identity1_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }
  ASSERT_EQ(public_id3, received_public_identity_);
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_identity1_]->ContactInfo(
                received_public_identity_,
                &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdWithReply) {
  boost::mutex mutex, mutex2;
  boost::condition_variable cond_var, cond_var2;
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Connect a slot which will reject the new contact
  bs2::connection connection(public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::ContactRequestSlot, this, args::_1, args::_2, &mutex, &cond_var)));

  std::string confirmed_contact;
  bs2::connection connection2(public_id2_->ConnectToContactConfirmedSignal(
      std::bind(&PublicIdTest::ContactConfirmedSlot, this, args::_1, args::_2,
                &confirmed_contact, &mutex2, &cond_var2)));

  // Send the message and start checking for messages
  ASSERT_EQ(kSuccess, public_id2_->SendContactInfo(public_identity2_, public_identity1_));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session2_->contact_handler_map()[public_identity2_]->ContactInfo(
                public_identity1_,
                &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  // Other side got message. Check status of contact and reply affirmatively.
  ASSERT_EQ(public_identity2_, received_public_identity_);
  received_contact = Contact();
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_identity1_]->ContactInfo(
                public_identity2_,
                &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
  ASSERT_EQ(kSuccess, public_id1_->ConfirmContact(public_identity1_, public_identity2_));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(interval_));

  // Contact should now be confirmed after reply
  received_contact = Contact();
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_identity1_]->ContactInfo(
                public_identity2_,
                &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);

  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  // Confirmation received, status should be updated
  ASSERT_EQ(public_identity1_, confirmed_contact);
  received_contact = Contact();
  ASSERT_EQ(kSuccess,
            session2_->contact_handler_map()[public_identity2_]->ContactInfo(
                public_identity1_,
                &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);
  ASSERT_FALSE(received_contact.inbox_name.empty());
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdWithRefusal) {
  boost::mutex mutex, mutex2;
  boost::condition_variable cond_var, cond_var2;
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Connect a slot which will reject the new contact
  bs2::connection connection(public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::ContactRequestSlot,
                this, args::_1, args::_2, &mutex, &cond_var)));

  std::string confirmed_contact;
  bs2::connection connection2(public_id2_->ConnectToContactConfirmedSignal(
      std::bind(&PublicIdTest::ContactConfirmedSlot, this, args::_1, args::_2,
                &confirmed_contact, &mutex2, &cond_var2)));

  // Send the message and start checking for messages
  ASSERT_EQ(kSuccess, public_id2_->SendContactInfo(public_identity2_, public_identity1_));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session2_->contact_handler_map()[public_identity2_]->ContactInfo(
                public_identity1_,
                &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  // Other side got message. Check status of contact and reply affirmatively.
  ASSERT_EQ(public_identity2_, received_public_identity_);
  received_contact = Contact();
  ASSERT_EQ(kSuccess,
            session1_->contact_handler_map()[public_identity1_]->ContactInfo(
                public_identity2_,
                &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
  ASSERT_EQ(kSuccess, public_id1_->ConfirmContact(public_identity1_, public_identity2_, false));
  received_contact = Contact();
  ASSERT_NE(kSuccess,
            session1_->contact_handler_map()[public_identity1_]->ContactInfo(
                public_identity2_,
                &received_contact));
}

TEST_F(PublicIdTest, FUNC_DisablePublicId) {
  boost::mutex mutex;
  boost::condition_variable cond_var;
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_->DisablePublicId(""));
  ASSERT_EQ(kGetPublicIdError, public_id1_->DisablePublicId("Rubbish"));

  ASSERT_EQ(kSuccess, public_id1_->DisablePublicId(public_identity1_));

  // Check a new user can't take this public username
  ASSERT_EQ(kStorePublicIdFailure, public_id2_->CreatePublicId(public_identity1_, false));
  ASSERT_EQ(kStorePublicIdFailure, public_id2_->CreatePublicId(public_identity1_, true));

  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Check user2 can't add itself to user1's MCID
  public_id1_->ConnectToNewContactSignal(
      std::bind(&PublicIdTest::NewContactSlot, this, args::_1, args::_2,
        &mutex, &cond_var));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSendContactInfoFailure, public_id2_->SendContactInfo(public_identity2_,
                                                                  public_identity1_));
  {
    bool ignore(true);
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2,
        std::bind(&PublicIdTest::ReceivedPublicUsernameEmpty, this, &ignore)));
  }
  ASSERT_TRUE(received_public_identity_.empty());

  // TODO(Qi,Ma): 2012-01-12 -Check if user2 alread in the MCID,
  //                  then it shall not be allowed to send msg to MMID anymore
}

TEST_F(PublicIdTest, FUNC_EnablePublicId) {
  boost::mutex mutex;
  boost::condition_variable cond_var;
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_->EnablePublicId(""));
  ASSERT_EQ(kGetPublicIdError, public_id1_->EnablePublicId("Rubbish"));

  ASSERT_EQ(kSuccess, public_id1_->DisablePublicId(public_identity1_));

  // Check user2 can't add itself to user1's MCID
  public_id1_->ConnectToNewContactSignal(std::bind(&PublicIdTest::NewContactSlot,
                                                   this, args::_1, args::_2, &mutex, &cond_var));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSendContactInfoFailure, public_id2_->SendContactInfo(public_identity2_,
                                                                  public_identity1_));
  {
    bool ignore(true);
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2,
        std::bind(&PublicIdTest::ReceivedPublicUsernameEmpty, this, &ignore)));
  }
  ASSERT_TRUE(received_public_identity_.empty());

  ASSERT_EQ(kSuccess, public_id1_->EnablePublicId(public_identity1_));

  // Check user2 can now add itself to user1's MCID
  public_id1_->ConnectToNewContactSignal(std::bind(&PublicIdTest::NewContactSlot, this,
                                                   args::_1, args::_2, &mutex, &cond_var));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess, public_id2_->SendContactInfo(public_identity2_, public_identity1_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }
  ASSERT_FALSE(received_public_identity_.empty());
}

TEST_F(PublicIdTest, FUNC_RemoveContact) {
  // Detailed msg exchanging behaviour tests are undertaken as part of
  // message_handler_test. Here only basic functionality is tested
  boost::mutex mutex;
  boost::condition_variable cond_var;
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_->RemoveContact(public_identity1_, ""));
  ASSERT_EQ(kPublicIdEmpty, public_id1_->RemoveContact("", public_identity2_));

  ASSERT_EQ(kLiveContactNotFound, public_id1_->RemoveContact(public_identity1_, public_identity2_));

  public_id1_->ConnectToNewContactSignal(std::bind(&PublicIdTest::NewContactSlot, this,
                                                   args::_1, args::_2, &mutex, &cond_var));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess, public_id2_->SendContactInfo(public_identity2_, public_identity1_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }
  ASSERT_FALSE(received_public_identity_.empty());

  ASSERT_EQ(kSuccess, public_id1_->RemoveContact(public_identity1_, public_identity2_));

  // Although sending msg is disallowed, sending contact_info shall be allowed
  received_public_identity_.clear();
  ASSERT_EQ(-77, public_id2_->SendContactInfo(public_identity2_, public_identity1_));
  ASSERT_EQ(kSuccess, public_id2_->RemoveContact(public_identity2_, public_identity1_));
  ASSERT_EQ(kSuccess, public_id2_->SendContactInfo(public_identity2_, public_identity1_));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }
  ASSERT_FALSE(received_public_identity_.empty());
}

TEST_F(PublicIdTest, FUNC_ContactList) {
  boost::mutex mutex;
  boost::condition_variable cond_var;
  int n(5), counter(0);
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  std::vector<std::string> usernames;
  for (int a(0); a < n; ++a) {
    usernames.push_back(public_identity2_ + boost::lexical_cast<std::string>(a));
    ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(usernames.at(a), true));
  }

  for (int y(0); y < n; ++y) {
    ASSERT_EQ(kSuccess,
              public_id2_->SendContactInfo(public_identity2_ + boost::lexical_cast<std::string>(y),
                                           public_identity1_));
  }

  public_id1_->ConnectToNewContactSignal(std::bind(&PublicIdTest::NewContactCounterSlot, this,
                                                   args::_1, args::_2, n, &counter, &mutex,
                                                   &cond_var));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_TRUE(cond_var.timed_wait(lock, interval_ * 2));
  }

  ContactMap contacts(public_id1_->ContactList(public_identity1_, kAlphabetical, kAll));
  ASSERT_EQ(size_t(n), contacts.size());
  for (auto it(usernames.begin()); it != usernames.end(); ++it)
    ASSERT_FALSE(contacts.find(*it) == contacts.end());
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
