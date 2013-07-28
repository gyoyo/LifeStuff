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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_

#include "maidsafe/data_store/surefile_store.h"

#include "maidsafe/routing/routing_api.h"

#include "maidsafe/nfs/nfs.h"
#include "maidsafe/nfs/pmid_registration.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff_manager/client_controller.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_storage.h"
#include "maidsafe/lifestuff/detail/routing_handler.h"

namespace maidsafe {
namespace lifestuff {

template<Product Product>
class ClientMaid {
 public:
  typedef std::unique_ptr<RoutingHandler> RoutingHandlerPtr;
  typedef RoutingHandler::EndPointVector EndPointVector;
  typedef nfs::PmidRegistration PmidRegistration;
  typedef lifestuff_manager::ClientController ClientController;
  typedef std::unique_ptr<ClientController> ClientControllerPtr;
  typedef nfs::ClientMaidNfs Storage;
  typedef std::unique_ptr<Storage> StoragePtr;
  typedef UserStorage<Storage> UserStorage;
  typedef passport::Passport Passport;
  typedef passport::Anmid Anmid;
  typedef passport::Ansmid Ansmid;
  typedef passport::Antmid Antmid;
  typedef passport::Anmaid Anmaid;
  typedef passport::Maid Maid;
  typedef passport::Pmid Pmid;
  typedef passport::Mid Mid;
  typedef passport::Tmid Tmid;

  ClientMaid(Session& session, const Slots& slots)
    : slots_(CheckSlots(slots)),
      session_(session),
      client_controller_(new ClientController(slots_.update_available)),
      storage_(),
      user_storage_(),
      routing_handler_() {
  }

  ~ClientMaid() {}

  void CreateUser(const Keyword& keyword,
                  const Pin& pin,
                  const Password& password,
                  const boost::filesystem::path& storage_path,
                  ReportProgressFunction& report_progress) {
    bool fobs_confirmed(false), drive_mounted(false);
    try {
      report_progress(kCreateUser, kCreatingUserCredentials);
      session_.passport().CreateFobs();
      Maid maid(session_.passport().Get<Maid>(false));
      report_progress(kCreateUser, kJoiningNetwork);
      JoinNetwork(maid);
      PutFreeFobs();
      report_progress(kCreateUser, kInitialisingClientComponents);
      storage_.reset(new Storage(routing_handler_->routing(), maid));
      report_progress(kCreateUser, kCreatingVault);
      Pmid pmid(session_.passport().Get<Pmid>(false));
      session_.set_storage_path(storage_path);
      client_controller_->StartVault(pmid, maid.name(), storage_path);
      RegisterPmid(maid, pmid);
      report_progress(kCreateUser, kCreatingUserCredentials);
      session_.passport().ConfirmFobs();
      fobs_confirmed = true;
      PutPaidFobs();
      session_.set_unique_user_id(Identity(RandomAlphaNumericString(64)));
      MountDrive(storage_path);
      drive_mounted = true;
      UnMountDrive();
      drive_mounted = false;
      session_.set_initialised();
      report_progress(kCreateUser, kStoringUserCredentials);
      PutSession(keyword, pin, password);
      session_.set_keyword_pin_password(keyword, pin, password);
    }
    catch(const std::exception& e) {
      UnCreateUser(fobs_confirmed, drive_mounted);
      boost::throw_exception(e);
    }
    return;
  }

  void LogIn(const Keyword& keyword,
             const Pin& pin,
             const Password& password,
             ReportProgressFunction& report_progress) {
    try {
      Anmaid anmaid;
      Maid maid(anmaid);
      report_progress(kLogin, kJoiningNetwork);
      JoinNetwork(maid);
      report_progress(kLogin, kInitialisingClientComponents);
      storage_.reset(new Storage(routing_handler_->routing(), maid));
      report_progress(kLogin, kRetrievingUserCredentials);
      GetSession(keyword, pin, password);
      maid = session_.passport().Get<Maid>(true);
      Pmid pmid(session_.passport().Get<Pmid>(true));
      report_progress(kLogin, kJoiningNetwork);
      JoinNetwork(maid);
      report_progress(kLogin, kInitialisingClientComponents);
      storage_.reset(new Storage(routing_handler_->routing(), maid));
      report_progress(kLogin, kStartingVault);
      client_controller_->StartVault(pmid, maid.name(), session_.storage_path());
      session_.set_keyword_pin_password(keyword, pin, password);
    }
    catch(const std::exception& e) {
      // client_controller_->StopVault(); get params!!!!!!!!!
      storage_.reset();
      boost::throw_exception(e);
    }
    return;
  }

  void LogOut() {
    //  client_controller_->StopVault(  );  parameters???
    UnMountDrive();
  }

  void MountDrive(const boost::filesystem::path&) {
    user_storage_.MountDrive(*storage_, session_);
    return;
  }

  void UnMountDrive() {
    user_storage_.UnMountDrive(session_);
    return;
  }

  void ChangeKeyword(const Keyword& old_keyword,
                     const Keyword& new_keyword,
                     const Pin& pin,
                     const Password& password,
                     ReportProgressFunction& report_progress) {
    report_progress(kChangeKeyword, kStoringUserCredentials);
    PutSession(new_keyword, pin, password);
    DeleteSession(old_keyword, pin);
    session_.set_keyword(new_keyword);
    return;
  }

  void ChangePin(const Keyword& keyword,
                 const Pin& old_pin,
                 const Pin& new_pin,
                 const Password& password,
                 ReportProgressFunction& report_progress) {
    report_progress(kChangePin, kStoringUserCredentials);
    PutSession(keyword, new_pin, password);
    DeleteSession(keyword, old_pin);
    session_.set_pin(new_pin);
    return;
  }

  void ChangePassword(const Keyword& keyword,
                      const Pin& pin,
                      const Password& new_password,
                      ReportProgressFunction& report_progress) {
    report_progress(kChangePassword, kStoringUserCredentials);
    PutSession(keyword, pin, new_password);
    session_.set_password(new_password);
    return;
  }

  boost::filesystem::path mount_path() {
    return user_storage_.mount_path();
  }

  boost::filesystem::path owner_path() {
    return user_storage_.owner_path();
  }

 private:

  const Slots& CheckSlots(const Slots& slots) {
    if (!slots.update_available)
      ThrowError(CommonErrors::uninitialised);
    if (!slots.network_health)
      ThrowError(CommonErrors::uninitialised);
    if (!slots.operations_pending)
      ThrowError(CommonErrors::uninitialised);
    return slots;
  }

  void PutSession(const Keyword& keyword, const Pin& pin, const Password& password) {
    NonEmptyString serialised_session(session_.Serialise());
    passport::EncryptedSession encrypted_session(passport::EncryptSession(
                                                    keyword, pin, password, serialised_session));
    Tmid tmid(encrypted_session, session_.passport().Get<Antmid>(true));
    passport::EncryptedTmidName encrypted_tmid_name(passport::EncryptTmidName(
                                                      keyword, pin, tmid.name()));
    Mid::name_type mid_name(passport::MidName(keyword, pin));
    Mid mid(mid_name, encrypted_tmid_name, session_.passport().Get<Anmid>(true));
    PutFob<Tmid>(tmid);
    PutFob<Mid>(mid);
  }

  void DeleteSession(const Keyword& keyword, const Pin& pin) {
    Mid::name_type mid_name(Mid::GenerateName(keyword, pin));
    auto mid_future(maidsafe::nfs::Get<Mid>(*storage_, mid_name));
    Mid mid(*mid_future.get());
    passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
    Tmid::name_type tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
    DeleteFob<Tmid>(tmid_name);
    DeleteFob<Mid>(mid_name);
  }

  void GetSession(const Keyword& keyword, const Pin& pin, const Password& password) {
    Mid::name_type mid_name(Mid::GenerateName(keyword, pin));
    auto mid_future(maidsafe::nfs::Get<Mid>(*storage_, mid_name));
    Mid mid(*mid_future.get());
    passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
    Tmid::name_type tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
    auto tmid_future(maidsafe::nfs::Get<Tmid>(*storage_, tmid_name));
    Tmid tmid(*tmid_future.get());
    passport::EncryptedSession encrypted_session(tmid.encrypted_session());
    NonEmptyString serialised_session(passport::DecryptSession(
                                        keyword, pin, password, encrypted_session));
    session_.Parse(serialised_session);
    session_.set_initialised();
  }

  void JoinNetwork(const Maid& maid) {
    PublicKeyRequestFunction public_key_request(
        [this](const NodeId& node_id, const GivePublicKeyFunctor& give_key) {
          PublicKeyRequest(node_id, give_key);
        });
    routing_handler_.reset(new RoutingHandler(maid, public_key_request));

    std::vector<boost::asio::ip::udp::endpoint> bootstrap_endpoints;
    client_controller_->GetBootstrapNodes(bootstrap_endpoints);
    EndPointVector endpoints;
    for (auto& endpoint : bootstrap_endpoints)
      endpoints.push_back(std::make_pair(endpoint.address().to_string(), endpoint.port()));

    routing_handler_->Join(endpoints);
  }

  void RegisterPmid(const Maid& maid, const Pmid& pmid) {
    PmidRegistration pmid_registration(maid, pmid, false);
    PmidRegistration::serialised_type serialised_pmid_registration(pmid_registration.Serialise());
    storage_->RegisterPmid(serialised_pmid_registration,
                        [this](std::string response) {
                          NonEmptyString serialised_response(response);
                          nfs::Reply::serialised_type serialised_reply(serialised_response);
                          nfs::Reply reply(serialised_reply);
                          if (!reply.IsSuccess())
                            ThrowError(VaultErrors::failed_to_handle_request);
                          this->slots_.network_health(std::stoi(reply.data().string()));
                        });
    return;
  }

  void UnregisterPmid(const Maid& maid, const Pmid& pmid) {
    PmidRegistration pmid_unregistration(maid, pmid, true);
    PmidRegistration::serialised_type serialised_pmid_unregistration(pmid_unregistration.Serialise());
    storage_->UnregisterPmid(serialised_pmid_unregistration, [](std::string) {});
    return;
  }

  void UnCreateUser(bool fobs_confirmed, bool drive_mounted) {
    if (fobs_confirmed) {
      Maid maid(session_.passport().Get<Maid>(fobs_confirmed));
      Pmid pmid(session_.passport().Get<Pmid>(fobs_confirmed));
      UnregisterPmid(maid, pmid);
    }
    // client_controller_->StopVault(); get params!!!!!!!!!
    if (drive_mounted)
      try { UnMountDrive(); } catch(...) { /* consume exception */ }
    storage_.reset();
    return;
  }

  template<typename Fob>
  void PutFob(const Fob& fob) {
    ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                          if (!reply.IsSuccess()) {
                            ThrowError(LifeStuffErrors::kStoreFailure);
                          }
                        });
    passport::Pmid::name_type pmid_name(session_.passport().Get<Pmid>(true).name());
    maidsafe::nfs::Put<Fob>(*storage_, fob, pmid_name, 3, reply);
    return;
  }

  template<typename Fob>
  void DeleteFob(const typename Fob::name_type& fob_name) {
    ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                          if (!reply.IsSuccess()) {
                            ThrowError(LifeStuffErrors::kDeleteFailure);
                          }
                        });
    maidsafe::nfs::Delete<Fob>(*storage_, fob_name, 3, reply);
    return;
  }

  template<typename Fob>
  Fob GetFob(const typename Fob::name_type& fob_name) {
    std::future<Fob> fob_future(maidsafe::nfs::Get<Fob>(*storage_, fob_name));
    return fob_future.get();
  }

  void PutFreeFobs() {
    ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                          if (!reply.IsSuccess()) {
                            ThrowError(VaultErrors::failed_to_handle_request);
                          }
                        });
    detail::PutFobs<Free>()(*storage_, session_.passport(), reply);
    return;
  }

  void PutPaidFobs() {
    ReplyFunction reply([this] (maidsafe::nfs::Reply reply) {
                          if (!reply.IsSuccess()) {
                            ThrowError(VaultErrors::failed_to_handle_request);
                          }
                        });
    detail::PutFobs<Paid>()(*storage_, session_.passport(), reply);
    return;
  }

  void PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key) {
    if (storage_) {
      typedef passport::PublicPmid PublicPmid;
      PublicPmid::name_type pmid_name(Identity(node_id.string()));
      auto pmid_future(maidsafe::nfs::Get<PublicPmid>(*storage_, pmid_name));
      give_key(pmid_future.get()->public_key());
    } else {
      ThrowError(CommonErrors::uninitialised);
    }
    return;
  }

  Slots slots_;
  Session& session_;
  ClientControllerPtr client_controller_;
  StoragePtr storage_;
  UserStorage user_storage_;
  RoutingHandlerPtr routing_handler_;
};

// SureFile Specialisation
// -----------------------

template<>
class ClientMaid<Product::kSureFile> {
 public:
  typedef lifestuff_manager::ClientController ClientController;
  typedef std::unique_ptr<ClientController> ClientControllerPtr;
  typedef data_store::SureFileStore Storage;
  typedef std::unique_ptr<Storage> StoragePtr;
  typedef UserStorage<Storage> UserStorage;
  typedef passport::Passport Passport;
  typedef passport::Anmid Anmid;
  typedef passport::Ansmid Ansmid;
  typedef passport::Antmid Antmid;
  typedef passport::Anmaid Anmaid;
  typedef passport::Maid Maid;
  typedef passport::Pmid Pmid;
  typedef passport::Mid Mid;
  typedef passport::Tmid Tmid;

  ClientMaid(Session& session, const Slots& slots)
    : slots_(CheckSlots(slots)),
      session_(session),
      client_controller_(),
      storage_(),
      user_storage_() {}

  ~ClientMaid() {}

  void CreateUser(const Keyword& keyword,
                  const Pin& pin,
                  const Password& password,
                  const boost::filesystem::path& storage_path,
                  ReportProgressFunction& report_progress) {
    report_progress(kCreateUser, kCreatingUserCredentials);
    session_.passport().CreateFobs();
    Maid maid(session_.passport().Get<Maid>(false));
    report_progress(kCreateUser, kInitialisingClientComponents);
    session_.passport().ConfirmFobs();
    session_.set_unique_user_id(Identity(RandomAlphaNumericString(64)));
    session_.set_initialised();
    session_.set_storage_path(storage_path);
    report_progress(kCreateUser, kStoringUserCredentials);
    PutSession(keyword, pin, password);
    session_.set_keyword_pin_password(keyword, pin, password);
    return;
  }

  void LogIn(const Keyword& keyword,
             const Pin& pin,
             const Password& password,
             ReportProgressFunction& report_progress) {
    report_progress(kLogin, kRetrievingUserCredentials);
    GetSession(keyword, pin, password);
    session_.set_keyword_pin_password(keyword, pin, password);
    return;
  }

  void LogOut() {
    UnMountDrive();
    return;
  }

  void MountDrive(const boost::filesystem::path& storage_path) {
    DiskUsage disk_usage(10995116277760);  // arbitrary 10GB
    storage_.reset(new Storage(storage_path, disk_usage));
    user_storage_.MountDrive(*storage_, session_);
    return;
  }

  void UnMountDrive() {
    user_storage_.UnMountDrive(session_);
    return;
  }

  void ChangeKeyword(const Keyword& old_keyword,
                     const Keyword& new_keyword,
                     const Pin& pin,
                     const Password& password,
                     ReportProgressFunction& report_progress) {
    report_progress(kChangeKeyword, kStoringUserCredentials);
    PutSession(new_keyword, pin, password);
    DeleteSession(old_keyword, pin);
    session_.set_keyword(new_keyword);
    return;
  }

  void ChangePin(const Keyword& keyword,
                 const Pin& old_pin,
                 const Pin& new_pin,
                 const Password& password,
                 ReportProgressFunction& report_progress) {
    report_progress(kChangePin, kStoringUserCredentials);
    PutSession(keyword, new_pin, password);
    DeleteSession(keyword, old_pin);
    session_.set_pin(new_pin);
    return;
  }

  void ChangePassword(const Keyword& keyword,
                      const Pin& pin,
                      const Password& new_password,
                      ReportProgressFunction& report_progress) {
    report_progress(kChangePassword, kStoringUserCredentials);
    PutSession(keyword, pin, new_password);
    session_.set_password(new_password);
    return;
  }

  boost::filesystem::path mount_path() {
    return user_storage_.mount_path();
  }

  boost::filesystem::path owner_path() {
    return user_storage_.owner_path();
  }

 private:
  const Slots& CheckSlots(const Slots& slots) {
    if (!slots.update_available)
      ThrowError(CommonErrors::uninitialised);
    if (!slots.operations_pending)
      ThrowError(CommonErrors::uninitialised);
    return slots;
  }

  void PutSession(const Keyword& keyword, const Pin& pin, const Password& password) {
    NonEmptyString serialised_session(session_.Serialise());
    passport::EncryptedSession encrypted_session(passport::EncryptSession(
                                                    keyword, pin, password, serialised_session));
    Tmid tmid(encrypted_session, session_.passport().Get<Antmid>(true));
    passport::EncryptedTmidName encrypted_tmid_name(passport::EncryptTmidName(
                                                      keyword, pin, tmid.name()));
    Mid::name_type mid_name(passport::MidName(keyword, pin));
    Mid mid(mid_name, encrypted_tmid_name, session_.passport().Get<Anmid>(true));
    storage_->Put(tmid.name(), tmid.Serialise());
    storage_->Put(mid_name, mid.Serialise());
    return;
  }

  void DeleteSession(const Keyword& keyword, const Pin& pin) {
    Mid::name_type mid_name(Mid::GenerateName(keyword, pin));
    NonEmptyString serialised_mid = storage_->Get(mid_name);
    Mid mid(mid_name, Mid::serialised_type(serialised_mid));
    passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
    Tmid::name_type tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
    storage_->Delete(tmid_name);
    storage_->Delete(mid_name);
    return;
  }

  void GetSession(const Keyword& keyword, const Pin& pin, const Password& password) {
    Mid::name_type mid_name(passport::Mid::GenerateName(keyword, pin));
    NonEmptyString serialised_mid = storage_->Get(mid_name);
    Mid mid(mid_name, passport::Mid::serialised_type(serialised_mid));
    passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
    Tmid::name_type tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
    NonEmptyString serialised_tmid(storage_->Get(tmid_name));
    Tmid tmid(tmid_name, Tmid::serialised_type(serialised_tmid));
    passport::EncryptedSession encrypted_session(tmid.encrypted_session());
    NonEmptyString serialised_session(passport::DecryptSession(
                                        keyword, pin, password, encrypted_session));
    session_.Parse(serialised_session);
    return;
  }

  Slots slots_;
  Session& session_;
  ClientControllerPtr client_controller_;
  StoragePtr storage_;
  UserStorage user_storage_;
};

}  // lifestuff
}  // maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_
