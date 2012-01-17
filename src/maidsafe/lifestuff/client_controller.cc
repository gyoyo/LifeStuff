/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  class which controls all maidsafe client operations
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENCE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include "maidsafe/lifestuff/client_controller.h"

#ifdef MAIDSAFE_WIN32
#  include <shlwapi.h>
#endif

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4308)
#endif
#include "boost/archive/text_oarchive.hpp"
#include "boost/archive/text_iarchive.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/foreach.hpp"

#include "maidsafe/common/buffered_chunk_store.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/session.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff {

class CCCallback {
 public:
  CCCallback()
      : return_int_(kPendingResult),
        mutex_(),
        cv_() {}

  void IntCallback(int return_code) {
    boost::mutex::scoped_lock lock(mutex_);
    return_int_ = return_code;
    cv_.notify_one();
  }

  int WaitForIntResult() {
    int result;
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (return_int_ == kPendingResult)
        cv_.wait(lock);
      result = return_int_;
      return_int_ = kPendingResult;
    }
    return result;
  }

 private:
  int return_int_;
  boost::mutex mutex_;
  boost::condition_variable cv_;
};


void PacketOpCallback(const int &store_manager_result,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var,
                      int *op_result) {
  boost::mutex::scoped_lock lock(*mutex);
  *op_result = store_manager_result;
  cond_var->notify_one();
}

ClientController::ClientController(std::shared_ptr<Session> session)
    : session_(session),
      packet_manager_(),
      auth_(new Authentication(session)),
      ser_da_(),
      surrogate_ser_da_(),
      initialised_(false),
      logging_out_(false),
      logged_in_(false) {}

ClientController::~ClientController() {
  packet_manager_->Close(false);
}

int ClientController::Initialise() {
  CCCallback cb;
  packet_manager_->Init(std::bind(&CCCallback::IntCallback, &cb, args::_1));
  int result(cb.WaitForIntResult());
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to initialise packet manager.";
    return result;
  }
  auth_->Init(packet_manager_);
  initialised_ = true;
  return kSuccess;
}

int ClientController::ParseDa() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }
  DataAtlas data_atlas;
  if (ser_da_.empty() && surrogate_ser_da_.empty()) {
    DLOG(ERROR) << "TMID brought is empty.";
    return -9000;
  }
  if (!data_atlas.ParseFromString(ser_da_)) {
    DLOG(ERROR) << "TMID doesn't parse.";
    return -9000;
  }
  if (!data_atlas.has_timestamp()) {
    DLOG(ERROR) << "DA doesn't have a timestamp.";
    return -9001;
  }
  if (!data_atlas.has_unique_user_id() || !data_atlas.has_root_parent_id()) {
    DLOG(ERROR) << "DA doesn't have keys for root directory.";
    return -9001;
  }
  session_->set_unique_user_id(data_atlas.unique_user_id());
  session_->set_root_parent_id(data_atlas.root_parent_id());
  DLOG(INFO) << "UUID: " << Base32Substr(session_->unique_user_id());
  DLOG(INFO) << "PID: " << Base32Substr(session_->root_parent_id());

  if (!data_atlas.has_serialised_keyring()) {
    DLOG(ERROR) << "Missing serialised keyring.";
    return -9003;
  }

  int n(session_->ParseKeyChain(data_atlas.serialised_keyring(),
                                data_atlas.serialised_selectables()));
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed ParseKeyChain: " << n;
    return -9003;
  }

  n = auth_->SetLoggedInData(ser_da_, surrogate_ser_da_);
  if (n != kSuccess) {
    DLOG(ERROR) << "Failed SetLoggedInData: " << n;
    return -9003;
  }

  std::set<std::string> public_usernames;
  std::string public_username;
  for (int n = 0; n < data_atlas.contacts_size(); ++n) {
    if (public_usernames.find(data_atlas.contacts(n).own_public_username()) ==
        public_usernames.end()) {
      session_->contact_handler_map().insert(
          std::make_pair(data_atlas.contacts(n).own_public_username(),
                         ContactsHandlerPtr(new ContactsHandler)));
      public_username = data_atlas.contacts(n).own_public_username();
    }
    Contact c(data_atlas.contacts(n));
    session_->contact_handler_map()[public_username]->AddContact(c);
  }

  return 0;
}

int ClientController::SerialiseDa() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }

  DataAtlas data_atlas;
  data_atlas.set_unique_user_id(session_->unique_user_id());
  data_atlas.set_root_parent_id(session_->root_parent_id());
  DLOG(INFO) << "UUID: " << Base32Substr(session_->unique_user_id());
  DLOG(INFO) << "PID: " << Base32Substr(session_->root_parent_id());
  data_atlas.set_timestamp(boost::lexical_cast<std::string>(
      GetDurationSinceEpoch().total_microseconds()));
  DLOG(INFO) << "data_atlas.set_timestamp: " << data_atlas.timestamp();

  std::string serialised_keyring, serialised_selectables;
  session_->SerialiseKeyChain(&serialised_keyring, &serialised_selectables);
  if (serialised_keyring.empty()) {
    DLOG(ERROR) << "Serialising keyring failed.";
    return -1;
  }
  data_atlas.set_serialised_keyring(serialised_keyring);
  data_atlas.set_serialised_selectables(serialised_selectables);

  std::vector<Contact> contacts;
  for (auto it(session_->contact_handler_map().begin());
       it != session_->contact_handler_map().end();
       ++it) {
    contacts.clear();
    (*it).second->OrderedContacts(&contacts);
    for (size_t n = 0; n < contacts.size(); ++n) {
      PublicContact *pc = data_atlas.add_contacts();
      pc->set_own_public_username((*it).first);
      pc->set_public_username(contacts[n].public_username);
      pc->set_mpid_name(contacts[n].mpid_name);
      pc->set_mmid_name(contacts[n].mmid_name);
      pc->set_status(contacts[n].status);
      pc->set_rank(contacts[n].rank);
      pc->set_last_contact(contacts[n].last_contact);
    }
  }

  ser_da_.clear();
  data_atlas.SerializeToString(&ser_da_);

  return 0;
}

bool ClientController::CreateUser(const std::string &username,
                                  const std::string &pin,
                                  const std::string &password) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }

  session_->ResetSession();
  int result = auth_->CreateUserSysPackets(username, pin);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create user system packets.";
    session_->ResetSession();
    return false;
  } else {
    DLOG(INFO) << "auth_->CreateUserSysPackets DONE.";
  }

  int n = SerialiseDa();
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }
  std::string ser_da(ser_da_);

  // Need different timestamps
  Sleep(boost::posix_time::milliseconds(1));
  n = SerialiseDa();
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return false;
  }
  std::string surrogate_ser_da(ser_da_);

  ser_da_ = ser_da;

  result = auth_->CreateTmidPacket(password, ser_da, surrogate_ser_da);
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot create tmid packet.";
    session_->ResetSession();
    return false;
  } else {
    DLOG(INFO) << "auth_->CreateTmidPacket DONE.";
  }

  session_->set_session_name(false);
  logged_in_ = true;
  return true;
}

int ClientController::CheckUserExists(const std::string &username,
                                      const std::string &pin) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }
  session_->ResetSession();
  session_->set_def_con_level(kDefCon1);
  ser_da_.clear();
  return auth_->GetUserInfo(username, pin);
}

bool ClientController::ValidateUser(const std::string &password) {
  if (!initialised_) {
    DLOG(ERROR) << "CC::ValidateUser - Not initialised.";
    return false;
  }
//  ser_da_.clear();

  std::string serialised_data_atlas, surrogate_serialised_data_atlas;
  int res(auth_->GetMasterDataMap(password,
                                  &serialised_data_atlas,
                                  &surrogate_serialised_data_atlas));
  if (res != 0) {
    DLOG(ERROR) << "CC::ValidateUser - Failed retrieving DA.";
    return false;
  }

  if (!serialised_data_atlas.empty()) {
    DLOG(INFO) << "ClientController::ValidateUser - Using TMID";
    ser_da_ = serialised_data_atlas;
    surrogate_ser_da_ = surrogate_serialised_data_atlas;
  } else if (!surrogate_serialised_data_atlas.empty()) {
    DLOG(INFO) << "ClientController::ValidateUser - Using STMID";
    surrogate_ser_da_ = surrogate_serialised_data_atlas;
  } else {
    // Password validation failed
//    session_->ResetSession();
    DLOG(INFO) << "ClientController::ValidateUser - Invalid password";
    return false;
  }

  session_->set_session_name(false);
  if (ParseDa() != 0) {
    DLOG(INFO) << "ClientController::ValidateUser - Cannot parse DA";
//    session_->ResetSession();
    return false;
  }
  logged_in_ = true;
  return true;
}

bool ClientController::Logout() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }

  logging_out_ = true;
//  clear_messages_thread_.join();
  int result = SaveSession();
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to save session " << result;
    return false;
  }

  ser_da_.clear();
  logging_out_ = false;
  logged_in_ = false;
  session_->ResetSession();
  return true;
}

int ClientController::SaveSession() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return kClientControllerNotInitialised;
  }

  int n = SerialiseDa();
  if (n != 0) {
    DLOG(ERROR) << "Failed to serialise DA.";
    return n;
  }

  n = kPendingResult;
  boost::mutex mutex;
  boost::condition_variable cond_var;
  VoidFuncOneInt func = std::bind(&PacketOpCallback, args::_1, &mutex,
                                  &cond_var, &n);
  auth_->SaveSession(ser_da_, func);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (n == kPendingResult)
      cond_var.wait(lock);
  }

  if (n != kSuccess) {
    if (n == kFailedToDeleteOldPacket) {
      DLOG(WARNING) << "Failed to delete old TMID otherwise saved session OK.";
    } else {
      DLOG(ERROR) << "Failed to Save Session.";
      return n;
    }
  }
  return 0;
}

bool ClientController::LeaveMaidsafeNetwork() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  if (auth_->RemoveMe() == kSuccess)
    return true;

  return false;
}

std::string ClientController::SessionName() {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return "";
  }
  return session_->session_name();
}

bool ClientController::ChangeUsername(const std::string &new_username) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  SerialiseDa();

  int result = auth_->ChangeUsername(ser_da_, new_username);
  if (result != kSuccess) {
    if (result == kFailedToDeleteOldPacket) {
      DLOG(WARNING) << "Failed to delete old packets, changed username OK.";
      return true;
    } else {
      DLOG(ERROR) << "Failed to change username.";
      return false;
    }
  }
  return true;
}

bool ClientController::ChangePin(const std::string &new_pin) {
  if (!initialised_) {
    DLOG(ERROR) << "Not initialised.";
    return false;
  }
  SerialiseDa();

  int result = auth_->ChangePin(ser_da_, new_pin);
  if (result != kSuccess) {
    if (result == kFailedToDeleteOldPacket) {
      DLOG(WARNING) << "Failed to delete old packets, otherwise changed PIN OK.";
      return true;
    } else {
      DLOG(ERROR) << "Failed to change PIN.";
      return false;
    }
  }
  return true;
}

bool ClientController::ChangePassword(const std::string &new_password) {
  if (!initialised_) {
    DLOG(ERROR) << " Not initialised.";
    return false;
  }
  SerialiseDa();

  int result = auth_->ChangePassword(ser_da_, new_password);
  if (result != kSuccess) {
    DLOG(ERROR) << " Authentication failed: " << result;
    return false;
  }
  return true;
}

std::string ClientController::Username() {
  return session_->username();
}

std::string ClientController::Pin() {
  return session_->pin();
}

std::string ClientController::Password() {
  return session_->password();
}

std::shared_ptr<ChunkStore> ClientController::client_chunk_store() const {
  return packet_manager_->chunk_store();
}

std::shared_ptr<PacketManager> ClientController::packet_manager() const {
  return packet_manager_;
}

}  // namespace lifestuff

}  // namespace maidsafe
