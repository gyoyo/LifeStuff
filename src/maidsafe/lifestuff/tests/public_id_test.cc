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
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/node.h"
#endif

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

namespace {

std::string GenerateMessage() {
  if (RandomUint32() % 2 == 0)
    return RandomAlphaNumericString(15);
  return "";
}

}  // namespace

typedef std::map<std::string, ContactStatus> ContactMap;

class PublicIdTest : public testing::TestWithParam<std::string> {
 public:
  PublicIdTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        session1_(),
        session2_(),
        remote_chunk_store1_(),
        remote_chunk_store2_(),
        public_id1_(),
        public_id2_(),
        asio_service1_(5),
        asio_service2_(5),
        public_identity1_("User 1 " + RandomAlphaNumericString(8)),
        public_identity2_("User 2 " + RandomAlphaNumericString(8)),
        received_public_identity_(),
        received_message_(),
#ifndef LOCAL_TARGETS_ONLY
        node1_(),
        node2_(),
#endif
        interval_(3) {}

  void NewContactSlot(const std::string&,
                      const std::string &contact_public_id,
                      const std::string& message,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var,
                      bool *done) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_identity_ = contact_public_id;
    received_message_ = message;
    *done = true;
    cond_var->notify_one();
  }

  void NewContactCounterSlot(const std::string&,
                             const std::string &contact_public_id,
                             const int &times,
                             int *counter,
                             boost::mutex* mutex,
                             boost::condition_variable* cond_var,
                             bool *done) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_identity_ = contact_public_id;
    ++(*counter);
    if (*counter == times) {
      *done = true;
      cond_var->notify_one();
    }
  }

  void ContactRequestSlot(const std::string&,
                          const std::string& contact_public_id,
                          const std::string& message,
                          boost::mutex* mutex,
                          boost::condition_variable *cond_var,
                          bool *done) {
    boost::mutex::scoped_lock lock(*mutex);
    received_public_identity_ = contact_public_id;
    received_message_ = message;
    *done = true;
    cond_var->notify_one();
  }

  void ContactConfirmedSlot(const std::string&,
                            const std::string &signal_public_id,
                            std::string *slot_public_id,
                            boost::mutex* mutex,
                            boost::condition_variable* cond_var,
                            bool *done) {
    boost::mutex::scoped_lock lock(*mutex);
    *slot_public_id  = signal_public_id;
    *done = true;
    cond_var->notify_one();
  }

 protected:
  void SetUp() {
    session1_.Reset();
    session2_.Reset();
    asio_service1_.Start();
    asio_service2_.Start();

#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store1_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service1_.service());
    remote_chunk_store2_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service2_.service());
#else
    remote_chunk_store1_ = BuildChunkStore(*test_dir_, &node1_);
    remote_chunk_store2_ = BuildChunkStore(*test_dir_, &node2_);
#endif

    public_id1_.reset(new PublicId(remote_chunk_store1_, session1_, asio_service1_.service()));

    public_id2_.reset(new PublicId(remote_chunk_store2_, session2_, asio_service2_.service()));
  }

  void TearDown() {
    public_id1_->StopCheckingForNewContacts();
    public_id2_->StopCheckingForNewContacts();
#ifndef LOCAL_TARGETS_ONLY
    node1_->Stop();
    node2_->Stop();
#endif
    asio_service1_.Stop();
    asio_service2_.Stop();
    remote_chunk_store1_->WaitForCompletion();
    remote_chunk_store2_->WaitForCompletion();
  }

  void CreateTestSignaturePackets(Session& session) {
    ASSERT_EQ(kSuccess, session.passport().CreateSigningPackets());
    ASSERT_EQ(kSuccess, session.passport().ConfirmSigningPackets());
  }

  std::shared_ptr<fs::path> test_dir_;
  Session session1_, session2_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store1_,
                                         remote_chunk_store2_;
  std::shared_ptr<PublicId> public_id1_, public_id2_;

  AsioService asio_service1_, asio_service2_;

  std::string public_identity1_, public_identity2_, received_public_identity_, received_message_;
#ifndef LOCAL_TARGETS_ONLY
  std::shared_ptr<pd::Node> node1_, node2_;
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

  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
        return PublicIdTest::NewContactSlot(own_public_id, contact_public_id, message, &mutex,
                                            &cond_var,
                                            &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  std::string message(RandomAlphaNumericString(10));

  ASSERT_NE(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));

  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_FALSE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(received_public_identity_.empty());
  ASSERT_TRUE(received_message_.empty());
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdSociable) {
  boost::mutex mutex;
  boost::condition_variable cond_var;
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
        return PublicIdTest::NewContactSlot(own_public_id, contact_public_id, message, &mutex,
                                            &cond_var,
                                            &done);
      });
  std::string message(GenerateMessage());
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  {
    boost::mutex::scoped_lock lock(mutex);
    ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);

  const ContactsHandlerPtr contacts_handler1(session1_.contacts_handler(public_identity1_));
  ASSERT_NE(nullptr, contacts_handler1.get());
  Contact received_contact;
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(received_public_identity_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);

  received_contact = Contact();
  done = false;
  std::string public_id3(public_identity2_ + "1");
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_id3, true));
  message = GenerateMessage();
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_id3, public_identity1_, message));
  {
    boost::mutex::scoped_lock lock(mutex);
    ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_EQ(public_id3, received_public_identity_);
  ASSERT_EQ(message, received_message_);
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(received_public_identity_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdWithReply) {
  boost::mutex mutex, mutex2;
  boost::condition_variable cond_var, cond_var2;
  bool done(false), done2(false);
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Connect a slot which will reject the new contact
  public_id1_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
        return PublicIdTest::ContactRequestSlot(own_public_id, contact_public_id, message, &mutex,
                                                &cond_var,
                                                &done);
      });

  std::string confirmed_contact;
  public_id2_->ConnectToContactConfirmedSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& /*timestamp*/) {
        return PublicIdTest::ContactConfirmedSlot(own_public_id, contact_public_id,
                                                  &confirmed_contact, &mutex2, &cond_var2, &done2);
      });

  // Send the message and start checking for messages
  std::string message(GenerateMessage());
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  const ContactsHandlerPtr contacts_handler2(session2_.contacts_handler(public_identity2_));
  ASSERT_NE(nullptr, contacts_handler2.get());
  Contact received_contact;
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  {
    boost::mutex::scoped_lock lock(mutex);
    ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  // Other side got message. Check status of contact and reply affirmatively.
  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);
  received_contact = Contact();
  const ContactsHandlerPtr contacts_handler1(session1_.contacts_handler(public_identity1_));
  ASSERT_NE(nullptr, contacts_handler1.get());
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);
  ASSERT_EQ(kSuccess, public_id1_->ConfirmContact(public_identity1_, public_identity2_));
  ASSERT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(interval_));

  // Contact should now be confirmed after reply
  received_contact = Contact();
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);

  {
    boost::mutex::scoped_lock lock(mutex2);
    ASSERT_TRUE(cond_var2.timed_wait(lock, interval_ * 2, [&] ()->bool { return done2; }));  // NOLINT (Dan)
  }

  // Confirmation received, status should be updated
  ASSERT_EQ(public_identity1_, confirmed_contact);
  received_contact = Contact();
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);
  ASSERT_FALSE(received_contact.inbox_name.empty());
}

TEST_F(PublicIdTest, FUNC_CreatePublicIdWithRefusal) {
  boost::mutex mutex;
  boost::condition_variable cond_var;
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  // Connect a slot which will reject the new contact
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
        return PublicIdTest::ContactRequestSlot(own_public_id, contact_public_id, message, &mutex,
                                                &cond_var,
                                                &done);
       });

  // Send the message and start checking for messages
  std::string message(GenerateMessage());
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  const ContactsHandlerPtr contacts_handler2(session2_.contacts_handler(public_identity2_));
  ASSERT_NE(nullptr, contacts_handler2.get());
  Contact received_contact;
  ASSERT_EQ(kSuccess, contacts_handler2->ContactInfo(public_identity1_, &received_contact));
  ASSERT_EQ(kRequestSent, received_contact.status);

  {
    boost::mutex::scoped_lock lock(mutex);
    ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  // Other side got message. Check status of contact and reply affirmatively.
  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);
  received_contact = Contact();
  const ContactsHandlerPtr contacts_handler1(session1_.contacts_handler(public_identity1_));
  ASSERT_NE(nullptr, contacts_handler1.get());
  ASSERT_EQ(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
  ASSERT_EQ(kPendingResponse, received_contact.status);

  ASSERT_EQ(kSuccess, public_id1_->RejectContact(public_identity1_, public_identity2_));
  received_contact = Contact();
  ASSERT_NE(kSuccess, contacts_handler1->ContactInfo(public_identity2_, &received_contact));
}

TEST_F(PublicIdTest, FUNC_FixAsynchronousConfirmedContact) {
  boost::mutex mutex;
  boost::condition_variable cond_var;
  bool done(false);
  // Create users who both accept new contacts
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  const ContactsHandlerPtr contacts_handler(session2_.contacts_handler(public_identity2_));
  Contact contact;
  contact.status = kConfirmed;
  asymm::Keys keys_mmid(session1_.passport().SignaturePacketDetails(passport::kMmid,
                                                               true,
                                                               public_identity1_));
  asymm::Keys keys_mpid(session1_.passport().SignaturePacketDetails(passport::kMpid,
                                                               true,
                                                               public_identity1_));

  contact.public_id = public_identity1_;
  contact.mpid_public_key = keys_mpid.public_key;
  contact.inbox_name = keys_mmid.identity;

  EXPECT_EQ(kSuccess, contacts_handler->AddContact(contact));

  std::string confirmed_contact;
  public_id1_->ConnectToContactConfirmedSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& /*timestamp*/) {
        return PublicIdTest::ContactConfirmedSlot(own_public_id, contact_public_id,
                                                  &confirmed_contact, &mutex, &cond_var, &done);
      });

  EXPECT_EQ(kSuccess, public_id1_->AddContact(public_identity1_, public_identity2_, ""));
  EXPECT_EQ(kSuccess, public_id2_->StartCheckingForNewContacts(interval_));
  EXPECT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  {
  boost::mutex::scoped_lock lock(mutex);
  ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 3, [&] ()->bool { return done; }));  // NOLINT (Alison)
  }

  ASSERT_EQ(public_identity2_, confirmed_contact);
  Contact received_contact;
  ASSERT_EQ(kSuccess,
            session1_.contacts_handler(public_identity1_)->ContactInfo(public_identity2_,
                                                                       &received_contact));
  ASSERT_EQ(kConfirmed, received_contact.status);
  ASSERT_FALSE(received_contact.inbox_name.empty());
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
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
        return PublicIdTest::NewContactSlot(own_public_id, contact_public_id, message, &mutex,
                                            &cond_var,
                                            &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  std::string message(RandomAlphaNumericString(10));
  ASSERT_EQ(kSendContactInfoFailure, public_id2_->AddContact(public_identity2_, public_identity1_,
                                                             message));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_FALSE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(received_public_identity_.empty());
  ASSERT_TRUE(received_message_.empty());

  // TODO(Qi,Ma): 2012-01-12 - Check if user2 alread in the MCID, then it shall not be allowed to
  //              send msg to MMID anymore
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
  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
        return PublicIdTest::NewContactSlot(own_public_id, contact_public_id, message, &mutex,
                                            &cond_var,
                                            &done);
      });

  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  std::string message(RandomAlphaNumericString(10));
  ASSERT_EQ(kSendContactInfoFailure, public_id2_->AddContact(public_identity2_, public_identity1_,
                                                             message));
  {
    boost::mutex::scoped_lock lock(mutex);
    EXPECT_FALSE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_TRUE(received_public_identity_.empty());
  ASSERT_TRUE(received_message_.empty());

  ASSERT_EQ(kSuccess, public_id1_->EnablePublicId(public_identity1_));

  // Check user2 can now add itself to user1's MCID
  message = GenerateMessage();
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, message));
  {
    boost::mutex::scoped_lock lock(mutex);
    ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_EQ(public_identity2_, received_public_identity_);
  ASSERT_EQ(message, received_message_);
}

TEST_F(PublicIdTest, FUNC_DeletePublicIdPacketVerification) {
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));

  passport::Passport& pass(session1_.passport());
  asymm::Keys mmid(pass.SignaturePacketDetails(passport::kMmid, true, public_identity1_)),
              mpid(pass.SignaturePacketDetails(passport::kMpid, true, public_identity1_)),
              anmpid(pass.SignaturePacketDetails(passport::kAnmpid, true, public_identity1_));
  std::string mcid_name(crypto::Hash<crypto::SHA512>(public_identity1_));

  ASSERT_EQ(kSuccess, public_id1_->DeletePublicId(public_identity1_));
  ASSERT_EQ("", remote_chunk_store1_->Get(mmid.identity));
  ASSERT_EQ("", remote_chunk_store1_->Get(mpid.identity));
  ASSERT_EQ("", remote_chunk_store1_->Get(anmpid.identity));
  ASSERT_EQ("", remote_chunk_store1_->Get(mcid_name));
  ASSERT_EQ("", remote_chunk_store1_->Get(mmid.identity,
                                          std::shared_ptr<asymm::Keys>(new asymm::Keys(mmid))));
  ASSERT_EQ("", remote_chunk_store1_->Get(mcid_name,
                                          std::shared_ptr<asymm::Keys>(new asymm::Keys(mpid))));

  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, false));
  mmid = pass.SignaturePacketDetails(passport::kMmid, true, public_identity1_);
  mpid = pass.SignaturePacketDetails(passport::kMpid, true, public_identity1_);
  anmpid = pass.SignaturePacketDetails(passport::kAnmpid, true, public_identity1_);
  mcid_name = crypto::Hash<crypto::SHA512>(public_identity1_);

  ASSERT_EQ(kSuccess, public_id1_->DeletePublicId(public_identity1_));
  ASSERT_EQ("", remote_chunk_store1_->Get(mmid.identity));
  ASSERT_EQ("", remote_chunk_store1_->Get(mpid.identity));
  ASSERT_EQ("", remote_chunk_store1_->Get(anmpid.identity));
  ASSERT_EQ("", remote_chunk_store1_->Get(mcid_name));
  ASSERT_EQ("", remote_chunk_store1_->Get(mmid.identity,
                                          std::shared_ptr<asymm::Keys>(new asymm::Keys(mmid))));
  ASSERT_EQ("", remote_chunk_store1_->Get(mcid_name,
                                          std::shared_ptr<asymm::Keys>(new asymm::Keys(mpid))));
}

TEST_F(PublicIdTest, FUNC_RemoveContact) {
  // Detailed msg exchanging behaviour tests are undertaken as part of
  // message_handler_test. Here only basic functionality is tested
  boost::mutex mutex;
  boost::condition_variable cond_var;
  ASSERT_EQ(kSuccess, public_id1_->CreatePublicId(public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->CreatePublicId(public_identity2_, true));

  ASSERT_EQ(kPublicIdEmpty, public_id1_->RemoveContact(public_identity1_, "", true));
  ASSERT_EQ(kPublicIdEmpty, public_id1_->RemoveContact("", public_identity2_, true));

  ASSERT_EQ(kContactNotFoundFailure,
            public_id1_->RemoveContact(public_identity1_, public_identity2_, true));

  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& message,
           const std::string& /*timestamp*/) {
          return PublicIdTest::NewContactSlot(own_public_id, contact_public_id, message, &mutex,
                                              &cond_var,
                                              &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, ""));
  {
    boost::mutex::scoped_lock lock(mutex);
    ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_FALSE(received_public_identity_.empty());

  done = false;
  ASSERT_EQ(kSuccess, public_id1_->RemoveContact(public_identity1_, public_identity2_, true));

  // Although sending msg is disallowed, sending contact_info shall be allowed
  received_public_identity_.clear();
  ASSERT_EQ(-77, public_id2_->AddContact(public_identity2_, public_identity1_, ""));
  ASSERT_EQ(kSuccess, public_id2_->RemoveContact(public_identity2_, public_identity1_, true));
  ASSERT_EQ(kSuccess, public_id2_->AddContact(public_identity2_, public_identity1_, ""));
  {
    boost::mutex::scoped_lock lock(mutex);
    ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }
  ASSERT_FALSE(received_public_identity_.empty());
  public_id1_->StopCheckingForNewContacts();
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

  std::string message;
  for (int y(0); y < n; ++y) {
    message = GenerateMessage();
    ASSERT_EQ(kSuccess,
              public_id2_->AddContact(public_identity2_ + boost::lexical_cast<std::string>(y),
                                      public_identity1_, message));
  }

  bool done(false);
  public_id1_->ConnectToNewContactSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& /*message*/,
           const std::string& /*timestamp*/) {
        return NewContactCounterSlot(own_public_id, contact_public_id, n, &counter, &mutex,
                                     &cond_var,
                                     &done);
      });
  ASSERT_EQ(kSuccess, public_id1_->StartCheckingForNewContacts(interval_));

  {
    boost::mutex::scoped_lock lock(mutex);
    ASSERT_TRUE(cond_var.timed_wait(lock, interval_ * 2, [&] ()->bool { return done; }));  // NOLINT (Dan)
  }

  ContactMap contacts(public_id1_->ContactList(public_identity1_, kAlphabetical, kAll));
  ASSERT_EQ(size_t(n), contacts.size());
  for (auto it(usernames.begin()); it != usernames.end(); ++it)
    ASSERT_FALSE(contacts.find(*it) == contacts.end());
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
