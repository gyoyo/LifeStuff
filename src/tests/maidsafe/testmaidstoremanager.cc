/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Compiler:     gcc
* Author:       Team
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <maidsafe/contact_info.pb.h>
#include <maidsafe/kademlia_service_messages.pb.h>
#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "maidsafe/vault/vaultservice.h"

namespace test_msm {

void DoneRun(const int &min_delay,
             const int &max_delay,
             google::protobuf::Closure* callback) {
  int min(min_delay);
  if (min < 0)
    min = 0;
  int diff = max_delay - min;
  if (diff < 1)
    diff = 1;
  int sleep_time(base::random_32bit_uinteger() % diff + min);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  callback->Run();
}

void ThreadedDoneRun(const int &min_delay,
                     const int &max_delay,
                     google::protobuf::Closure* callback) {
  boost::thread(DoneRun, min_delay, max_delay, callback);
}

void ConditionNotifyNoFlag(int set_return,
                           int *return_value,
                           maidsafe::GenericConditionData *generic_cond_data) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(
      base::random_32bit_uinteger() % 1000 + 5000));
  boost::lock_guard<boost::mutex> lock(generic_cond_data->cond_mutex);
  *return_value = set_return;
  generic_cond_data->cond_variable->notify_all();
}

void FailedContactCallback(
    const kad::Contact &holder,
    const int &min_delay,
    const int &max_delay,
    std::vector< boost::shared_ptr<maidsafe::ChunkHolder> > *packet_holders,
    boost::shared_ptr<maidsafe::GenericConditionData> cond_data) {
  int diff = max_delay - min_delay;
  int sleep_time(base::random_32bit_uinteger() % diff + min_delay);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  boost::shared_ptr<maidsafe::ChunkHolder> failed_chunkholder(
      new maidsafe::ChunkHolder(kad::Contact(holder.node_id(), "", 0)));
  failed_chunkholder->status = maidsafe::kFailedHolder;
  boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
  packet_holders->push_back(failed_chunkholder);
  cond_data->cond_variable->notify_all();
}

void ContactCallback(
    const kad::Contact &holder,
    const int &min_delay,
    const int &max_delay,
    std::vector< boost::shared_ptr<maidsafe::ChunkHolder> > *packet_holders,
    boost::shared_ptr<maidsafe::GenericConditionData> cond_data) {
  int diff = max_delay - min_delay;
  int sleep_time(base::random_32bit_uinteger() % diff + min_delay);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  boost::shared_ptr<maidsafe::ChunkHolder>
      chunkholder(new maidsafe::ChunkHolder(holder));
  chunkholder->status = maidsafe::kContactable;
  boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
  packet_holders->push_back(chunkholder);
  cond_data->cond_variable->notify_all();
}

void ThreadedGetHolderContactCallbacks(
    const std::vector<kad::Contact> &holders,
    const int &failures,
    const int &min_delay,
    const int &max_delay,
    std::vector< boost::shared_ptr<maidsafe::ChunkHolder> > *packet_holders,
    boost::shared_ptr<maidsafe::GenericConditionData> cond_data) {
  int min(min_delay);
  if (min < 0)
    min = 0;
  int max(max_delay);
  if (max - min < 1)
    max = min + 1;
  for (size_t i = 0, failed = 0; i < holders.size(); ++i) {
    // Add 500ms to each delay, to allow holders to callback in order
    min += 500;
    max += 500;
    if (static_cast<int>(failed) < failures) {
      boost::thread thr(FailedContactCallback, holders.at(i), min, max,
          packet_holders, cond_data);
      ++failed;
    } else {
      boost::thread thr(ContactCallback, holders.at(i), min, max,
          packet_holders, cond_data);
    }
  }
}

void PacketOpCallback(const int &store_manager_result,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var,
                      int *op_result) {
  boost::mutex::scoped_lock lock(*mutex);
  *op_result = store_manager_result;
  cond_var->notify_one();
}

void RunDeletePacketCallbacks(
    std::list< boost::function < void(boost::shared_ptr<
        maidsafe::DeletePacketData>) > > functors,
    boost::shared_ptr<maidsafe::DeletePacketData> delete_data) {
  while (functors.size()) {
    functors.front()(delete_data);
    functors.pop_front();
  }
}

}  // namespace test_msm

namespace maidsafe {

class MaidStoreManagerTest : public testing::Test {
 protected:
  MaidStoreManagerTest() : test_root_dir_(file_system::FileSystem::TempDir() +
                                 "/maidsafe_TestMSM"),
                           client_chunkstore_dir_(test_root_dir_+"/Chunkstore"),
                           client_chunkstore_(),
                           client_pmid_keys_(),
                           client_maid_keys_(),
                           client_pmid_public_signature_(),
                           hex_client_pmid_(),
                           client_pmid_(),
                           mutex_(),
                           crypto_(),
                           cond_var_(),
                           functor_(boost::bind(&test_msm::PacketOpCallback, _1,
                               &mutex_, &cond_var_, &packet_op_result_)) {
    try {
      boost::filesystem::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("In MaidStoreManagerTest ctor - %s\n", e.what());
    }
    fs::create_directories(test_root_dir_);
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    client_maid_keys_.GenerateKeys(kRsaKeySize);
    std::string maid_pri = client_maid_keys_.private_key();
    std::string maid_pub = client_maid_keys_.public_key();
    std::string maid_pub_key_signature = crypto_.AsymSign(maid_pub, "",
        maid_pri, crypto::STRING_STRING);
    std::string maid_name = crypto_.Hash(maid_pub + maid_pub_key_signature, "",
        crypto::STRING_STRING, true);
    SessionSingleton::getInstance()->AddKey(MAID, maid_name, maid_pri, maid_pub,
        maid_pub_key_signature);
    client_pmid_keys_.GenerateKeys(kRsaKeySize);
    std::string pmid_pri = client_pmid_keys_.private_key();
    std::string pmid_pub = client_pmid_keys_.public_key();
    client_pmid_public_signature_ = crypto_.AsymSign(pmid_pub, "",
        maid_pri, crypto::STRING_STRING);
    hex_client_pmid_ = crypto_.Hash(pmid_pub +
        client_pmid_public_signature_, "", crypto::STRING_STRING, true);
    client_pmid_ = base::DecodeFromHex(hex_client_pmid_);
    SessionSingleton::getInstance()->AddKey(PMID, hex_client_pmid_, pmid_pri,
        pmid_pub, client_pmid_public_signature_);
    SessionSingleton::getInstance()->SetConnectionStatus(0);
  }

  virtual ~MaidStoreManagerTest() {
    try {
      SessionSingleton::getInstance()->ResetSession();
      boost::filesystem::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("In MaidStoreManagerTest dtor - %s\n", e.what());
    }
  }

  virtual void SetUp() {
    client_chunkstore_ = boost::shared_ptr<ChunkStore>
        (new ChunkStore(client_chunkstore_dir_, 0, 0));
    ASSERT_TRUE(client_chunkstore_->Init());
    boost::uint64_t count(0);
    while (count < 60000 && !client_chunkstore_->is_initialised()) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
  }
  virtual void TearDown() {}

  std::string test_root_dir_, client_chunkstore_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  crypto::RsaKeyPair client_pmid_keys_, client_maid_keys_;
  std::string client_pmid_public_signature_, hex_client_pmid_, client_pmid_;
  boost::mutex mutex_;
  crypto::Crypto crypto_;
  boost::condition_variable cond_var_;
  int packet_op_result_;
  VoidFuncOneInt functor_;

 private:
  MaidStoreManagerTest(const MaidStoreManagerTest&);
  MaidStoreManagerTest &operator=(const MaidStoreManagerTest&);
};

class MockMsmKeyUnique : public MaidsafeStoreManager {
 public:
  explicit MockMsmKeyUnique(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD5(FindValue, int(const std::string &kad_key,
                              bool check_local,
                              kad::ContactInfo *cache_holder,
                              std::vector<std::string> *chunk_holders_ids,
                              std::string *needs_cache_copy_id));
  MOCK_METHOD4(FindAndLoadChunk, int(
      const std::string &chunk_name,
      const std::vector<std::string> &chunk_holders_ids,
      bool load_data,
      std::string *data));
  MOCK_METHOD1(SendChunk, int(const StoreData &store_data));
  MOCK_METHOD2(AddToWatchList, void(
      const StoreData &store_data,
      const StorePrepResponse &store_prep_response));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_KeyUnique) {
  MockMsmKeyUnique msm(client_chunkstore_);
  std::string non_hex_key = crypto_.Hash("a", "", crypto::STRING_STRING, false);
  std::string hex_key = base::EncodeToHex(non_hex_key);
  EXPECT_CALL(msm, FindValue(non_hex_key, true, testing::_, testing::_,
      testing::_)).WillOnce(testing::Return(1))
      .WillOnce(testing::Return(kSuccess));
  EXPECT_CALL(msm, FindValue(non_hex_key, false, testing::_, testing::_,
      testing::_)).WillOnce(testing::Return(1))
      .WillOnce(testing::Return(kSuccess));
  ASSERT_TRUE(msm.KeyUnique(hex_key, true));
  ASSERT_TRUE(msm.KeyUnique(hex_key, false));
  ASSERT_FALSE(msm.KeyUnique(hex_key, true));
  ASSERT_FALSE(msm.KeyUnique(hex_key, false));
}
/*
TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_PrepareToSendChunk) {
  MockMsmKeyUnique msm(client_chunkstore_);
  ASSERT_TRUE(client_chunkstore_->is_initialised());
  std::string non_hex_key = crypto_.Hash("A", "", crypto::STRING_STRING, false);
  std::string hex_key = base::EncodeToHex(non_hex_key);
  // Set up data for calls to FindValue
  kad::ContactInfo cache_holder;
  cache_holder.set_node_id(crypto_.Hash("B", "", crypto::STRING_STRING, false));
  cache_holder.set_ip("192.168.3.3");
  cache_holder.set_port(8888);
  std::vector<std::string> chunk_holders_ids;
  StorePrepResponse empty_store_prep_response;
  for (int i = 0; i < 10; ++i) {
    chunk_holders_ids.push_back(crypto_.Hash(base::itos(i * i), "",
                                crypto::STRING_STRING, false));
  }
  std::string needs_cache_copy_id = crypto_.Hash("C", "", crypto::STRING_STRING,
                                                 false);
  std::string key_id1, public_key1, public_key_signature1, private_key1;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id1, &public_key1,
      &public_key_signature1, &private_key1);
  StoreData store_data(non_hex_key, 10, (kHashable | kNormal), PRIVATE, "",
      key_id1, public_key1, public_key_signature1, private_key1);

  // Set expectations
  EXPECT_CALL(msm, FindValue(non_hex_key, false, testing::_, testing::_,
      testing::_))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::Return(kSuccess)))  // Call 1
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(kSuccess)))  // Call 2
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(kSuccess)))  // Call 3
      .WillOnce(testing::Return(kFindValueFailure))  // Call 4
      .WillOnce(testing::Return(kFindValueError));  // Call 5
  EXPECT_CALL(msm, AddToWatchList(
      testing::AllOf(testing::Field(&StoreData::non_hex_key, non_hex_key),
                     testing::Field(&StoreData::dir_type, PRIVATE),
                     testing::Field(&StoreData::public_key,
                                    client_pmid_keys_.public_key()),
                     testing::Field(&StoreData::private_key,
                                    client_pmid_keys_.private_key()),
                     testing::Field(&StoreData::public_key_signature,
                                    client_pmid_public_signature_)),
      testing::_))
          .Times(2);  // Calls 1 & 2
  EXPECT_CALL(msm, FindAndLoadChunk(non_hex_key, chunk_holders_ids, false,
      testing::_))
          .WillOnce(testing::Return(kSuccess))  // Call 2
          .WillOnce(testing::Return(kLoadedChunkEmpty));  // Call 3
  EXPECT_CALL(msm, SendChunk(
      testing::AllOf(testing::Field(&StoreData::non_hex_key, non_hex_key),
                     testing::Field(&StoreData::dir_type, PRIVATE),
                     testing::Field(&StoreData::public_key,
                                    client_pmid_keys_.public_key()),
                     testing::Field(&StoreData::private_key,
                                    client_pmid_keys_.private_key()),
                     testing::Field(&StoreData::public_key_signature,
                                    client_pmid_public_signature_))))
          .Times(2 * kMinChunkCopies);  // Call 3 (x 4) & Call 4 (x 4)

  // Run test calls
  for (int i = 0; i < 5; ++i) {
    msm.PrepareToSendChunk(store_data);
  }
  // Allow time for AddToWatchList call
  boost::this_thread::sleep(boost::posix_time::seconds(1));
}
*/
TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_GetStoreRequests) {
  MaidsafeStoreManager msm(client_chunkstore_);
  std::string recipient_id = crypto_.Hash("RecipientID", "",
      crypto::STRING_STRING, false);
  StorePrepRequest store_prep_request;
  StoreChunkRequest store_chunk_request;
  // Make chunk/packet names
  std::vector<std::string> names;
  for (int i = 100; i < 117; ++i) {
    std::string j(base::itos(i));
    names.push_back(crypto_.Hash(j, "", crypto::STRING_STRING, false));
  }

  // Check bad data - ensure existing parameters in requests are cleared
  store_prep_request.set_chunkname(names.at(0));
  store_chunk_request.set_chunkname(names.at(0));
  ASSERT_NE("", store_prep_request.chunkname());
  ASSERT_NE("", store_chunk_request.chunkname());
  std::string key_id2, public_key2, public_key_signature2, private_key2;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id2, &public_key2,
      &public_key_signature2, &private_key2);
  StoreData st_missing_name("", 10, (kHashable | kNormal), PRIVATE, "", key_id2,
      public_key2, public_key_signature2, private_key2);
  ASSERT_EQ(kChunkNotInChunkstore, msm.GetStoreRequests(st_missing_name,
      recipient_id, &store_prep_request, &store_chunk_request));
  ASSERT_EQ("", store_prep_request.chunkname());
  ASSERT_EQ("", store_chunk_request.chunkname());

  // Check PRIVATE_SHARE chunk
  std::string msid_name = crypto_.Hash("b", "", crypto::STRING_STRING, true);
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(kRsaKeySize);
  std::vector<std::string> attributes;
  attributes.push_back("PrivateShare");
  attributes.push_back(msid_name);
  attributes.push_back(rsakp.public_key());
  attributes.push_back(rsakp.private_key());
  std::list<ShareParticipants> participants;
  ShareParticipants sp;
  sp.id = "spid";
  sp.public_key = "pub_key";
  sp.role = 'A';
  participants.push_back(sp);
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(kSuccess, SessionSingleton::getInstance()->
      AddPrivateShare(attributes, share_stats, &participants));
  std::string key_id3, public_key3, public_key_signature3, private_key3;
  msm.GetChunkSignatureKeys(PRIVATE_SHARE, msid_name, &key_id3, &public_key3,
      &public_key_signature3, &private_key3);
  StoreData st_chunk_private_share(names.at(0), 3, (kHashable | kOutgoing),
      PRIVATE_SHARE, msid_name, key_id3, public_key3, public_key_signature3,
      private_key3);
  ASSERT_EQ(kSuccess,
      client_chunkstore_->AddChunkToOutgoing(names.at(0), std::string("100")));
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(st_chunk_private_share, recipient_id,
      &store_prep_request, &store_chunk_request));
  std::string public_key_signature = crypto_.AsymSign(rsakp.public_key(), "",
      rsakp.private_key(), crypto::STRING_STRING);
  std::string request_signature = crypto_.AsymSign(crypto_.Hash(
      public_key_signature + names.at(0) + recipient_id, "",
      crypto::STRING_STRING, false), "", rsakp.private_key(),
      crypto::STRING_STRING);
  std::string size_signature = crypto_.AsymSign(base::itos_ull(3), "",
      rsakp.private_key(), crypto::STRING_STRING);

  ASSERT_EQ(names.at(0), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.signed_size().pmid());
  ASSERT_EQ(rsakp.public_key(), store_prep_request.signed_size().public_key());
  ASSERT_EQ(public_key_signature,
      store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(size_signature, store_prep_request.signed_size().signature());
  ASSERT_EQ(request_signature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(0), store_chunk_request.chunkname());
  ASSERT_EQ("100", store_chunk_request.data());
  ASSERT_EQ(client_pmid_, store_chunk_request.pmid());
  ASSERT_EQ(rsakp.public_key(), store_chunk_request.public_key());
  ASSERT_EQ(public_key_signature, store_chunk_request.public_key_signature());
  ASSERT_EQ(request_signature, store_chunk_request.request_signature());
  ASSERT_EQ(DATA, store_chunk_request.data_type());

  // Check PUBLIC_SHARE chunk
  std::string key_id4, public_key4, public_key_signature4, private_key4;
  msm.GetChunkSignatureKeys(PUBLIC_SHARE, "", &key_id4, &public_key4,
      &public_key_signature4, &private_key4);
  StoreData st_chunk_public_share_bad(names.at(1), 3, (kHashable | kOutgoing),
      PUBLIC_SHARE, "", key_id4, public_key4, public_key_signature4,
      private_key4);
  client_chunkstore_->AddChunkToOutgoing(names.at(1), std::string("101"));
  ASSERT_EQ(kGetRequestSigError, msm.GetStoreRequests(st_chunk_public_share_bad,
      recipient_id, &store_prep_request, &store_chunk_request));
  rsakp.GenerateKeys(kRsaKeySize);
  std::string anmpid_pri = rsakp.private_key();
  std::string anmpid_pub = rsakp.public_key();
  std::string anmpid_pub_sig = crypto_.AsymSign(anmpid_pub, "", anmpid_pri,
      crypto::STRING_STRING);
  std::string anmpid_name = crypto_.Hash("Anmpid", "", crypto::STRING_STRING,
      true);
  SessionSingleton::getInstance()->AddKey(ANMPID, anmpid_name, anmpid_pri,
      anmpid_pub, anmpid_pub_sig);
  rsakp.GenerateKeys(kRsaKeySize);
  std::string mpid_pri = rsakp.private_key();
  std::string mpid_pub = rsakp.public_key();
  std::string mpid_pub_sig = crypto_.AsymSign(mpid_pub, "",
      anmpid_pri, crypto::STRING_STRING);
  std::string mpid_name = crypto_.Hash("PublicName", "", crypto::STRING_STRING,
      true);
  SessionSingleton::getInstance()->AddKey(MPID, mpid_name, mpid_pri, mpid_pub,
      mpid_pub_sig);
  msm.GetChunkSignatureKeys(PUBLIC_SHARE, "", &key_id4, &public_key4,
      &public_key_signature4, &private_key4);
  StoreData st_chunk_public_share_good(names.at(1), 3, (kHashable | kOutgoing),
      PUBLIC_SHARE, "", key_id4, public_key4, public_key_signature4,
      private_key4);
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(st_chunk_public_share_good,
      recipient_id, &store_prep_request, &store_chunk_request));
  request_signature = crypto_.AsymSign(crypto_.Hash(
      mpid_pub_sig + names.at(1) + recipient_id, "", crypto::STRING_STRING,
      false), "", mpid_pri, crypto::STRING_STRING);
  size_signature = crypto_.AsymSign(base::itos_ull(3), "", mpid_pri,
      crypto::STRING_STRING);

  ASSERT_EQ(names.at(1), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.signed_size().pmid());
  ASSERT_EQ(mpid_pub, store_prep_request.signed_size().public_key());
  ASSERT_EQ(mpid_pub_sig,
      store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(size_signature, store_prep_request.signed_size().signature());
  ASSERT_EQ(request_signature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(1), store_chunk_request.chunkname());
  ASSERT_EQ("101", store_chunk_request.data());
  ASSERT_EQ(client_pmid_, store_chunk_request.pmid());
  ASSERT_EQ(mpid_pub, store_chunk_request.public_key());
  ASSERT_EQ(mpid_pub_sig, store_chunk_request.public_key_signature());
  ASSERT_EQ(request_signature, store_chunk_request.request_signature());
  ASSERT_EQ(DATA, store_chunk_request.data_type());

  // Check ANONYMOUS chunk
  std::string key_id5, public_key5, public_key_signature5, private_key5;
  msm.GetChunkSignatureKeys(ANONYMOUS, "", &key_id5, &public_key5,
      &public_key_signature5, &private_key5);
  StoreData st_chunk_anonymous(names.at(2), 3, (kHashable | kOutgoing),
      ANONYMOUS, "", key_id5, public_key5, public_key_signature5, private_key5);
  client_chunkstore_->AddChunkToOutgoing(names.at(2), std::string("102"));
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(st_chunk_anonymous, recipient_id,
      &store_prep_request, &store_chunk_request/*, &iou_done_request*/));

  ASSERT_EQ(names.at(2), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.signed_size().pmid());
  ASSERT_EQ(" ", store_prep_request.signed_size().public_key());
  ASSERT_EQ(" ", store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(kAnonymousRequestSignature,
    store_prep_request.signed_size().signature());
  ASSERT_EQ(kAnonymousRequestSignature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(2), store_chunk_request.chunkname());
  ASSERT_EQ("102", store_chunk_request.data());
  ASSERT_EQ(client_pmid_, store_chunk_request.pmid());
  ASSERT_EQ(" ", store_chunk_request.public_key());
  ASSERT_EQ(" ", store_chunk_request.public_key_signature());
  ASSERT_EQ(kAnonymousRequestSignature,
            store_chunk_request.request_signature());
  ASSERT_EQ(PDDIR_NOTSIGNED, store_chunk_request.data_type());

  // Check PRIVATE chunk
  std::string key_id6, public_key6, public_key_signature6, private_key6;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id6, &public_key6,
      &public_key_signature6, &private_key6);
  StoreData st_chunk_private(names.at(3), 3, (kHashable | kOutgoing), PRIVATE,
      "", key_id6, public_key6, public_key_signature6, private_key6);
  client_chunkstore_->AddChunkToOutgoing(names.at(3), std::string("103"));
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(st_chunk_private, recipient_id,
      &store_prep_request, &store_chunk_request));
  request_signature = crypto_.AsymSign(crypto_.Hash(
      client_pmid_public_signature_ + names.at(3) + recipient_id, "",
      crypto::STRING_STRING, false), "", client_pmid_keys_.private_key(),
      crypto::STRING_STRING);
  size_signature = crypto_.AsymSign(base::itos_ull(3), "",
      client_pmid_keys_.private_key(), crypto::STRING_STRING);

  ASSERT_EQ(names.at(3), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.signed_size().pmid());
  ASSERT_EQ(client_pmid_keys_.public_key(),
      store_prep_request.signed_size().public_key());
  ASSERT_EQ(client_pmid_public_signature_,
      store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(size_signature, store_prep_request.signed_size().signature());
  ASSERT_EQ(request_signature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(3), store_chunk_request.chunkname());
  ASSERT_EQ("103", store_chunk_request.data());
  ASSERT_EQ(client_pmid_, store_chunk_request.pmid());
  ASSERT_EQ(client_pmid_keys_.public_key(), store_chunk_request.public_key());
  ASSERT_EQ(client_pmid_public_signature_,
      store_chunk_request.public_key_signature());
  ASSERT_EQ(request_signature, store_chunk_request.request_signature());
  ASSERT_EQ(DATA, store_chunk_request.data_type());
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_ValidatePrepResp) {
  MaidsafeStoreManager msm(client_chunkstore_);
  // Make peer keys
  crypto::RsaKeyPair peer_pmid_keys;
  peer_pmid_keys.GenerateKeys(kRsaKeySize);
  std::string peer_pmid_pri = peer_pmid_keys.private_key();
  std::string peer_pmid_pub = peer_pmid_keys.public_key();
  std::string peer_pmid_pub_signature = crypto_.AsymSign(peer_pmid_pub, "",
      peer_pmid_pri, crypto::STRING_STRING);
  std::string peer_pmid = crypto_.Hash(peer_pmid_pub + peer_pmid_pub_signature,
      "", crypto::STRING_STRING, false);
  // Make request
  StorePrepRequest store_prep_request;
  StoreChunkRequest store_chunk_request;
  std::string chunk_value(base::RandomString(163));
  std::string chunk_name(crypto_.Hash(chunk_value, "", crypto::STRING_STRING,
      false));
  StoreData store_data(chunk_name, chunk_value.size(), (kHashable | kOutgoing),
      PRIVATE, "", client_pmid_, client_pmid_keys_.public_key(),
      client_pmid_public_signature_, client_pmid_keys_.private_key());
  client_chunkstore_->AddChunkToOutgoing(chunk_name, chunk_value);
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(store_data, peer_pmid,
      &store_prep_request, &store_chunk_request));
  // Make proper response
  maidsafe_vault::VaultChunkStore
      vault_chunkstore(test_root_dir_ + "/VaultChunkstore", 999999, 0);
  maidsafe_vault::VaultService vault_service(peer_pmid_pub, peer_pmid_pri,
      peer_pmid_pub_signature, &vault_chunkstore, NULL, NULL, NULL, 0);
  StorePrepResponse good_store_prep_response;
  google::protobuf::Closure *done =
      google::protobuf::NewCallback(&google::protobuf::DoNothing);
  vault_service.StorePrep(NULL, &store_prep_request,
                          &good_store_prep_response, done);

  // Uninitialised StorePrepResponse
  StorePrepResponse store_prep_response;
  ASSERT_EQ(kSendPrepResponseUninitialised, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Uninitialised StoreContract
  store_prep_response = good_store_prep_response;
  store_prep_response.clear_store_contract();
  ASSERT_EQ(kSendPrepResponseUninitialised, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Uninitialised InnerContract
  store_prep_response = good_store_prep_response;
  StoreContract *mutable_store_contract =
      store_prep_response.mutable_store_contract();
  mutable_store_contract->clear_inner_contract();
  ASSERT_EQ(kSendPrepResponseUninitialised, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Wrong PMID
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  mutable_store_contract->set_pmid(client_pmid_);
  ASSERT_EQ(kSendPrepPeerError, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Altered SignedSize
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  StoreContract::InnerContract *mutable_inner_contract =
      mutable_store_contract->mutable_inner_contract();
  SignedSize *mutable_signed_size =
      mutable_inner_contract->mutable_signed_size();
  mutable_signed_size->set_data_size(chunk_value.size() - 1);
  ASSERT_EQ(kSendPrepSignedSizeAltered, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Returned kNack
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  mutable_inner_contract = mutable_store_contract->mutable_inner_contract();
  mutable_inner_contract->set_result(kNack);
  ASSERT_EQ(kSendPrepFailure, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // PMID doesn't validate
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  std::string wrong_pmid = crypto_.Hash(base::RandomString(100), "",
      crypto::STRING_STRING, false);
  mutable_store_contract->set_pmid(wrong_pmid);
  ASSERT_EQ(kSendPrepInvalidId, msm.ValidatePrepResponse(wrong_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // PMID didn't sign StoreContract correctly
  store_prep_response = good_store_prep_response;
  store_prep_response.set_response_signature(crypto_.AsymSign(
      base::RandomString(100), "", peer_pmid_pri, crypto::STRING_STRING));
  ASSERT_EQ(kSendPrepInvalidResponseSignature, msm.ValidatePrepResponse(
      peer_pmid, store_prep_request.signed_size(), &store_prep_response));

  // PMID didn't sign InnerContract correctly
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  mutable_store_contract->set_signature(crypto_.AsymSign(base::RandomString(99),
      "", peer_pmid_pri, crypto::STRING_STRING));
  std::string ser_bad_contract;
  mutable_store_contract->SerializeToString(&ser_bad_contract);
  store_prep_response.set_response_signature(crypto_.AsymSign(ser_bad_contract,
      "", peer_pmid_pri, crypto::STRING_STRING));
  ASSERT_EQ(kSendPrepInvalidContractSignature, msm.ValidatePrepResponse(
      peer_pmid, store_prep_request.signed_size(), &store_prep_response));

  // All OK
  ASSERT_EQ(kSuccess, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &good_store_prep_response));
}

class MockMsmSendChunk : public MaidsafeStoreManager {
 public:
  explicit MockMsmSendChunk(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD3(AssessTaskStatus, TaskStatus(const StoreData &store_data,
                                            StoreTaskType task_type,
                                            StoreTask *task));
  MOCK_METHOD4(GetStorePeer, int(const float &ideal_rtt,
                                 const std::vector<kad::Contact> &exclude,
                                 kad::Contact *new_peer,
                                 bool *local));
  MOCK_METHOD2(WaitForOnline, bool(const std::string &data_name,
                                   const StoreTaskType &task_type));
  MOCK_METHOD5(SendPrep, int(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      StorePrepRequest *store_prep_request,
      StorePrepResponse *store_prep_response));
  MOCK_METHOD4(SendContent, int(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      StoreChunkRequest *store_chunk_request));
  MOCK_METHOD2(AddToWatchList, void(
      const StoreData &store_data,
      const StorePrepResponse &store_prep_response));
  MOCK_METHOD3(SendPacket, void(const StoreData &store_data,
                                     int *return_value,
                                     GenericConditionData *generic_cond_data));
};

TEST_F(MaidStoreManagerTest, FUNC_MAID_MSM_SendChunk) {
  MockMsmSendChunk msm(client_chunkstore_);
  std::string chunkname = crypto_.Hash("ddd", "", crypto::STRING_STRING, false);
  std::string hex_chunkname = base::EncodeToHex(chunkname);
  client_chunkstore_->AddChunkToOutgoing(chunkname, std::string("ddd"));
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  StoreData store_data(chunkname, 3, (kHashable | kOutgoing), PRIVATE, "",
      key_id, public_key, public_key_signature, private_key);
  std::string peername = crypto_.Hash("peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.1", 9999);
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.non_hex_key,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  StoreTask task(store_data.non_hex_key, kStoreChunk, store_data.size,
      kMinChunkCopies, kMaxStoreFailures);  // For call 7
  task.active_subtask_count_ = 1;  // For call 7
  StoreTask task1(store_data.non_hex_key, kStoreChunk, store_data.size,
      kMinChunkCopies, kMaxStoreFailures);  // For call 11
  task1.success_count_ = 1;  // For call 11
  StoreTask task2(store_data.non_hex_key, kStoreChunk, store_data.size,
      kMinChunkCopies, kMaxStoreFailures);  // For call 12
  task2.success_count_ = 2;  // For call 12
  StoreTask task3(store_data.non_hex_key, kStoreChunk, store_data.size,
      kMinChunkCopies, kMaxStoreFailures);  // For call 13
  task3.success_count_ = 3;  // For call 13
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  EXPECT_CALL(msm, AssessTaskStatus(testing::_, kStoreChunk, testing::_))
      .Times(21)
      .WillOnce(testing::Return(kCompleted))  // Call 1
      .WillOnce(testing::Return(kCancelled))  // Call 2
      .WillOnce(testing::Return(kPending))  // Call 3
      .WillOnce(testing::Return(kStarted))  // Call 4
      .WillOnce(testing::Return(kStarted))  // Call 5
      .WillOnce(testing::Return(kStarted))  // Call 6
      .WillOnce(testing::Return(kCompleted))  // Call 6
      .WillOnce(testing::Return(kStarted))  // Call 7
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(task),
          testing::Return(kCancelled)))  // Call 7
      .WillOnce(testing::Return(kStarted))  // Call 8
      .WillOnce(testing::Return(kStarted))  // Call 8
      .WillOnce(testing::Return(kStarted))  // Call 9
      .WillOnce(testing::Return(kStarted))  // Call 9
      .WillOnce(testing::Return(kStarted))  // Call 10
      .WillOnce(testing::Return(kStarted))  // Call 10
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(task1),
          testing::Return(kStarted)))  // Call 11
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(task1),
          testing::Return(kStarted)))  // Call 11
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(task2),
          testing::Return(kStarted)))  // Call 12
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(task2),
          testing::Return(kStarted)))  // Call 12
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(task3),
          testing::Return(kStarted)))  // Call 13
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(task3),
          testing::Return(kStarted)));  // Call 13
  EXPECT_CALL(msm, GetStorePeer(testing::_, testing::_, testing::_, testing::_))
      .Times(11)
      .WillOnce(testing::Return(kGetStorePeerError))  // Call 3
      .WillRepeatedly(DoAll(testing::SetArgumentPointee<2>(peer),
                            testing::Return(kSuccess)));
  EXPECT_CALL(msm, WaitForOnline(chunkname, kStoreChunk))
      .Times(18)
      .WillOnce(testing::Return(false))  // Call 4
      .WillOnce(testing::Return(true))  // Call 5
      .WillOnce(testing::Return(true))  // Call 6
      .WillOnce(testing::Return(true))  // Call 7
      .WillOnce(testing::Return(true))  // Call 8
      .WillOnce(testing::Return(false))  // Call 8
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(msm, SendPrep(testing::_, testing::_, testing::_, testing::_,
      testing::_))
      .Times(9)
      .WillOnce(testing::Return(kSendPrepFailure))  // Call 5
      .WillRepeatedly(testing::Return(kSuccess));
  EXPECT_CALL(msm, SendContent(testing::_, testing::_, testing::_, testing::_))
      .Times(7)
      .WillOnce(testing::Return(kSendContentFailure))  // Call 9
      .WillOnce(testing::Return(kSendContentFailure))  // Call 9
      .WillOnce(testing::Return(kSendContentFailure))  // Call 10
      .WillRepeatedly(testing::Return(kSuccess));
  EXPECT_CALL(msm, AddToWatchList(testing::_, testing::_)).Times(1);  // Call 10

  ASSERT_EQ(kStoreAlreadyCompleted, msm.SendChunk(store_data));  // Call 1
  // The follwoing should cause the task to be removed
  ASSERT_EQ(kStoreCancelled, msm.SendChunk(store_data));  // Call 2
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.non_hex_key,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kGetStorePeerError, msm.SendChunk(store_data));  // Call 3
  ASSERT_EQ(kTaskCancelledOffline, msm.SendChunk(store_data));  // Call 4
  ASSERT_EQ(kSendPrepFailure, msm.SendChunk(store_data));  // Call 5
  // The following implies the task is deleted - so delete the task and restart
  ASSERT_EQ(kStoreAlreadyCompleted, msm.SendChunk(store_data));  // Call 6
  ASSERT_EQ(kSuccess, msm.tasks_handler_.DeleteTask(store_data.non_hex_key,
      kStoreChunk, ""));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.non_hex_key,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  // The following should cause the task to be removed
  ASSERT_EQ(kStoreCancelled, msm.SendChunk(store_data));  // Call 7
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.non_hex_key,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kTaskCancelledOffline, msm.SendChunk(store_data));  // Call 8
  ASSERT_EQ(kSendContentFailure, msm.SendChunk(store_data));  // Call 9
  ASSERT_EQ(kSuccess, msm.SendChunk(store_data));  // Call 10
  ASSERT_EQ(kSuccess, msm.SendChunk(store_data));  // Call 11
  ASSERT_EQ(kSuccess, msm.SendChunk(store_data));  // Call 12
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  // The follwoing should cause the task to be removed
  ASSERT_EQ(kSuccess, msm.SendChunk(store_data));  // Call 13
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
}

class MockMsmStoreLoadPacket : public MaidsafeStoreManager {
 public:
  explicit MockMsmStoreLoadPacket(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD5(FindValue, int(const std::string &kad_key,
                              bool check_local,
                              kad::ContactInfo *cache_holder,
                              std::vector<std::string> *chunk_holders_ids,
                              std::string *needs_cache_copy_id));
  MOCK_METHOD1(SendPacket, void(boost::shared_ptr<StoreData> store_data));
  MOCK_METHOD1(DeletePacketFromNet,
               void(boost::shared_ptr<DeletePacketData> delete_data));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_StoreNewPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);

  // Add keys to Session
  crypto::RsaKeyPair anmid_keys;
  anmid_keys.GenerateKeys(kRsaKeySize);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string anmid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, true);
  SessionSingleton::getInstance()->AddKey(ANMID, anmid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);

  // Set up packet for storing
  std::string packet_name = crypto_.Hash(base::RandomString(100), "",
                                         crypto::STRING_STRING, false);
  std::string hex_packet_name = base::EncodeToHex(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetPacketSignatureKeys(MID, PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  ASSERT_EQ(anmid_name, key_id);
  ASSERT_EQ(anmid_pub, public_key);
  ASSERT_EQ(anmid_pub_key_signature, public_key_signature);
  ASSERT_EQ(anmid_pri, private_key);
  std::string packet_value = base::RandomString(200);

  // Set up test requirements
  kad::ContactInfo cache_holder;
  cache_holder.set_node_id("a");
  std::string ser_kad_store_response_cant_parse("Rubbish");
  std::string ser_kad_store_response_empty;
  std::string ser_kad_store_response_good, ser_kad_store_response_fail;
  kad::StoreResponse store_response;
  store_response.set_result(kad::kRpcResultSuccess);
  store_response.SerializeToString(&ser_kad_store_response_good);
  store_response.set_result("Fail");
  store_response.SerializeToString(&ser_kad_store_response_fail);

  // Set up expectations
  EXPECT_CALL(msm, FindValue(packet_name, true, testing::_, testing::_,
      testing::_))
          .Times(6)
          .WillOnce(testing::Return(-1))  // Call 3
          .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
                          testing::Return(kSuccess)))  // Call 4
          .WillRepeatedly(testing::Return(kFindValueFailure));

  EXPECT_CALL(msm, SendPacket(testing::_))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_empty, _1))))  // Call 5
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_cant_parse, _1))))  // Call 6
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_fail, _1))))  // Call 7
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_good, _1))));  // Call 8

  // Call 1 - Check with bad packet name length
  packet_op_result_ = kGeneralError;
  msm.StorePacket("InvalidName", packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kIncorrectKeySize, packet_op_result_);

  // Call 2 - Check with bad packet type
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, static_cast<PacketType>(-1),
                  PRIVATE, "", kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kPacketUnknownType, packet_op_result_);

  // Call 3 - FindValue fails
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketFindValueFailure, packet_op_result_);

  // Call 4 - FindValue yields a cached copy
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketCached, packet_op_result_);

  // Call 5 - SendPacket returns no result
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketError, packet_op_result_);

  // Call 6 - SendPacket returns unparseable result
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketParseError, packet_op_result_);

  // Call 7 - SendPacket returns failure
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketFailure, packet_op_result_);

  // Call 8 - SendPacket returns success
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_StoreExistingPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);

  // Add keys to Session
  crypto::RsaKeyPair anmid_keys;
  anmid_keys.GenerateKeys(kRsaKeySize);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string anmid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, true);
  SessionSingleton::getInstance()->AddKey(ANMID, anmid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);

  // Set up packet for storing
  std::string packet_name = crypto_.Hash(base::RandomString(100), "",
                                         crypto::STRING_STRING, false);
  std::string hex_packet_name = base::EncodeToHex(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetPacketSignatureKeys(MID, PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  ASSERT_EQ(anmid_name, key_id);
  ASSERT_EQ(anmid_pub, public_key);
  ASSERT_EQ(anmid_pub_key_signature, public_key_signature);
  ASSERT_EQ(anmid_pri, private_key);
  std::string packet_value = base::RandomString(200);

  // Set up store response
  std::string ser_kad_store_response_good;
  kad::StoreResponse store_response;
  store_response.set_result(kad::kRpcResultSuccess);
  store_response.SerializeToString(&ser_kad_store_response_good);

  // Set up serialised Kademlia delete responses
  std::string ser_kad_delete_response_cant_parse("Rubbish");
  std::string ser_kad_delete_response_empty;
  std::string ser_kad_delete_response_good, ser_kad_delete_response_fail;
  kad::DeleteResponse delete_response;
  delete_response.set_result(kad::kRpcResultSuccess);
  delete_response.SerializeToString(&ser_kad_delete_response_good);
  delete_response.set_result("Fail");
  delete_response.SerializeToString(&ser_kad_delete_response_fail);

  // Set up lists of DeletePacketCallbacks using serialised Kad delete responses
  const size_t kExistingValueCount(5);
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_good;
  for (size_t i = 0; i < kExistingValueCount - 1; ++i) {
    functors_kad_good.push_back(boost::bind(
        &MaidsafeStoreManager::DeletePacketCallback, &msm,
        ser_kad_delete_response_good, _1));
  }
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_empty(functors_kad_good),
      functors_kad_cant_parse(functors_kad_good),
      functors_kad_fail(functors_kad_good);
  functors_kad_empty.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_empty, _1));
  functors_kad_cant_parse.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_cant_parse, _1));
  functors_kad_fail.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_fail, _1));
  functors_kad_good.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_good, _1));

  // Set up vector of existing values
  std::vector<std::string> existing_values;
  for (size_t i = 0; i < kExistingValueCount; ++i)
    existing_values.push_back("ExistingValue" + base::itos(i));

  // Set up expectations
  EXPECT_CALL(msm, FindValue(packet_name, true, testing::_, testing::_,
      testing::_))
          .Times(8)
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(existing_values),
                                testing::Return(kSuccess)));

  EXPECT_CALL(msm, SendPacket(testing::_))
      .Times(2)
      .WillRepeatedly(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_good, _1))));  // Calls 3 & 8

  EXPECT_CALL(msm, DeletePacketFromNet(testing::_))  // Calls 5 to 8 inclusive
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_empty, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_cant_parse, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_fail, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))));

  // Call 1 - If exists kDoNothingReturnFailure
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnFailure, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketAlreadyExists, packet_op_result_);

  // Call 2 - If exists kDoNothingReturnSuccess
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 3 - If exists kAppend
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kAppend,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 4 - Invalid IfExists
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  static_cast<IfPacketExists>(-1), functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketUnknownExistsType, packet_op_result_);

  // Call 5 - If exists kOverwrite - DeleteResponse empty
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketError, packet_op_result_);

  // Call 6 - If exists kOverwrite - DeleteResponse doesn't parse
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketParseError, packet_op_result_);

  // Call 7 - If exists kOverwrite - DeleteResponse fails
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFailure, packet_op_result_);

  // Call 8 - If exists kOverwrite - DeleteResponse passes
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_LoadPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);

  // Set up test requirements
  std::vector<std::string> packet_names, hex_packet_names;
  const size_t kTestCount(6);
  packet_names.push_back("InvalidName");
  hex_packet_names.push_back("InvalidName");
  for (size_t i = 1; i < kTestCount; ++i) {
    packet_names.push_back(crypto_.Hash(base::RandomString(100), "",
                                        crypto::STRING_STRING, false));
    hex_packet_names.push_back(base::EncodeToHex(packet_names.at(i)));
  }
  std::vector<std::string> values, returned_values;
  const size_t kValueCount(5);
  for (size_t i = 0; i < kValueCount; ++i)
    values.push_back("Value" + base::itos(i));
  kad::ContactInfo cache_holder;
  cache_holder.set_node_id("a");

  // Set up expectations
  EXPECT_CALL(msm, FindValue(packet_names.at(1), false, testing::_, testing::_,
      testing::_))
          .Times(kMaxChunkLoadRetries)
          .WillRepeatedly(testing::Return(-1));  // Call 2

  EXPECT_CALL(msm, FindValue(packet_names.at(2), false, testing::_, testing::_,
      testing::_))
          .Times(kMaxChunkLoadRetries)
          .WillRepeatedly(testing::Return(kSuccess));  // Call 3

  EXPECT_CALL(msm, FindValue(packet_names.at(3), false, testing::_, testing::_,
      testing::_))
          .Times(kMaxChunkLoadRetries)
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<2>(cache_holder),
                                testing::Return(kSuccess)));  // Call 4

  EXPECT_CALL(msm, FindValue(packet_names.at(4), false, testing::_, testing::_,
      testing::_))  // Call 5
          .WillOnce(testing::Return(-1))
          .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
                          testing::Return(kSuccess)))
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(values),
                          testing::Return(kSuccess)));

  EXPECT_CALL(msm, FindValue(packet_names.at(5), false, testing::_, testing::_,
      testing::_))  // Call 6
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(values),
                          testing::Return(kSuccess)));

  // Call 1 - Check with bad packet name length
  size_t test_number(0);
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kIncorrectKeySize,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 2 - FindValue fails
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueFailure,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 3 - FindValue claims success but doesn't populate value vector
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueFailure,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 4 - FindValue yields a cached copy
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueFailure,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 5 - Success
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kSuccess,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(kValueCount), returned_values.size());
  for (size_t i = 0; i < kValueCount; ++i)
    ASSERT_EQ(values.at(i), returned_values.at(i));

  // Call 6 - Single value success
  ++test_number;
  std::string returned_value("Fud");
  ASSERT_EQ(kSuccess,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_value));
  ASSERT_EQ(values.at(0), returned_value);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_DeletePacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);

  // Add keys to Session
  crypto::RsaKeyPair anmid_keys;
  anmid_keys.GenerateKeys(kRsaKeySize);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string anmid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, true);
  SessionSingleton::getInstance()->AddKey(ANMID, anmid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);

  // Set up packet for deletion
  std::string packet_name = crypto_.Hash(base::RandomString(100), "",
                                         crypto::STRING_STRING, false);
  std::string hex_packet_name = base::EncodeToHex(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetPacketSignatureKeys(MID, PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  ASSERT_EQ(anmid_name, key_id);
  ASSERT_EQ(anmid_pub, public_key);
  ASSERT_EQ(anmid_pub_key_signature, public_key_signature);
  ASSERT_EQ(anmid_pri, private_key);
  const size_t kValueCount(5);
  std::vector<std::string> packet_values, single_value;
  for (size_t i = 0; i < kValueCount; ++i)
    packet_values.push_back("Value" + base::itos(i));
  single_value.push_back("Value");

  // Set up serialised Kademlia delete responses
  std::string ser_kad_delete_response_cant_parse("Rubbish");
  std::string ser_kad_delete_response_empty;
  std::string ser_kad_delete_response_good, ser_kad_delete_response_fail;
  kad::DeleteResponse delete_response;
  delete_response.set_result(kad::kRpcResultSuccess);
  delete_response.SerializeToString(&ser_kad_delete_response_good);
  delete_response.set_result("Fail");
  delete_response.SerializeToString(&ser_kad_delete_response_fail);

  // Set up lists of DeletePacketCallbacks using serialised Kad delete responses
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_good;
  for (size_t i = 0; i < kValueCount - 1; ++i) {
    functors_kad_good.push_back(boost::bind(
        &MaidsafeStoreManager::DeletePacketCallback, &msm,
        ser_kad_delete_response_good, _1));
  }
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_empty(functors_kad_good),
      functors_kad_cant_parse(functors_kad_good),
      functors_kad_fail(functors_kad_good);
  functors_kad_empty.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_empty, _1));
  functors_kad_cant_parse.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_cant_parse, _1));
  functors_kad_fail.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_fail, _1));
  functors_kad_good.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_good, _1));

  // Set up expectations
  EXPECT_CALL(msm, FindValue(packet_name, false, testing::_, testing::_,
      testing::_))
          .Times(5)
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(single_value),
                          testing::Return(kSuccess)))  // Call 9
          .WillOnce(testing::Return(kFindNodesFailure))  // Call 10
          .WillOnce(testing::Return(-1))  // Call 11
          .WillOnce(testing::Return(kSuccess))  // Call 12
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(packet_values),
                          testing::Return(kSuccess)));  // Call 13

  EXPECT_CALL(msm, DeletePacketFromNet(testing::_))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_empty, _1))))  // 3
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_cant_parse, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_fail, _1))))  // 5
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))))  // 6
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &MaidsafeStoreManager::DeletePacketCallback, &msm,
          ser_kad_delete_response_fail, _1))))  // Call 7
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &MaidsafeStoreManager::DeletePacketCallback, &msm,
          ser_kad_delete_response_good, _1))))  // Call 8
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))))  // 9
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))));  // 13

  // Call 1 - Check with bad packet name length
  packet_op_result_ = kGeneralError;
  msm.DeletePacket("InvalidName", packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kIncorrectKeySize, packet_op_result_);

  // Call 2 - Invalid PacketType
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, static_cast<PacketType>(-1),
                   PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kPacketUnknownType, packet_op_result_);

  // Call 3 - Multiple value request - DeleteResponse empty
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketError, packet_op_result_);

  // Call 4 - Multiple value request - DeleteResponse doesn't parse
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketParseError, packet_op_result_);

  // Call 5 - Multiple value request - DeleteResponse fails
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFailure, packet_op_result_);

  // Call 6 - Multiple value request - DeleteResponse passes
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 7 - Single value request - DeleteResponse fails
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, single_value.at(0), MID, PRIVATE, "",
                   functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFailure, packet_op_result_);

  // Call 8 - Single value request - DeleteResponse success
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, single_value.at(0), MID, PRIVATE, "",
                   functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 9 - Single value empty request - DeleteResponse success
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, "", MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 10 - No values - Packet already deleted from net
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 11 - No values - FindValue returns failure
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFindValueFailure, packet_op_result_);

  // Call 12 - No values - FindValue returns success but doesn't populate values
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFindValueFailure, packet_op_result_);

  // Call 13 - No values - FindValue succeeds
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);
}

}  // namespace maidsafe
