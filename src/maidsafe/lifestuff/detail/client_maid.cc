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

#include "maidsafe/lifestuff/detail/client_maid.h"

namespace maidsafe {
namespace lifestuff {

ClientMaid::ClientMaid(Session& session, const Slots& slots)
    : slots_(CheckSlots(slots)),
      session_(session),
      client_controller_(new ClientController(slots_.update_available)),
      storage_(),
      user_storage_(),
      routing_handler_() {}

ClientMaid::~ClientMaid() {}

void ClientMaid::CreateUser(const Keyword& keyword, const Pin& pin, const Password& password,
                            const boost::filesystem::path& storage_path,
                            ReportProgressFunction& report_progress) {
  bool fobs_confirmed(false), drive_mounted(false);
  try {
    report_progress(kCreateUser, kCreatingUserCredentials);
    session_.passport().CreateFobs();
    Maid maid(session_.passport().template Get<Maid>(false));
    report_progress(kCreateUser, kJoiningNetwork);
    JoinNetwork(maid);
    PutFreeFobs();
    report_progress(kCreateUser, kInitialisingClientComponents);
    PublicPmid::Name pmid_name(session_.passport().template Get<Pmid>(true).name());
    storage_.reset(
        new Storage(routing_handler_->asio_service(), routing_handler_->routing(), pmid_name));
    report_progress(kCreateUser, kCreatingVault);
    Pmid pmid(session_.passport().template Get<Pmid>(false));
    session_.set_storage_path(storage_path);
    client_controller_->StartVault(pmid, maid.name(), storage_path);
    RegisterPmid(maid, pmid);
    report_progress(kCreateUser, kCreatingUserCredentials);
    session_.passport().ConfirmFobs();
    fobs_confirmed = true;
    PutPaidFobs();
    session_.set_unique_user_id(Identity(RandomAlphaNumericString(64)));
    MountDrive();
    drive_mounted = true;
    UnMountDrive();
    drive_mounted = false;
    session_.set_initialised();
    report_progress(kCreateUser, kStoringUserCredentials);
    PutSession(keyword, pin, password);
    session_.set_keyword_pin_password(keyword, pin, password);
  }
  catch (const std::exception& e) {
    UnCreateUser(fobs_confirmed, drive_mounted);
    boost::throw_exception(e);
  }
  return;
}

void ClientMaid::LogIn(const Keyword& keyword, const Pin& pin, const Password& password,
                       const boost::filesystem::path& /*storage_path*/,
                       ReportProgressFunction& report_progress) {
  try {
    Anmaid anmaid;
    Maid maid(anmaid);
    report_progress(kLogin, kJoiningNetwork);
    JoinNetwork(maid);
    report_progress(kLogin, kInitialisingClientComponents);
    PublicPmid::Name pmid_name(Pmid(maid).name());
    storage_.reset(
        new Storage(routing_handler_->asio_service(), routing_handler_->routing(), pmid_name));
    report_progress(kLogin, kRetrievingUserCredentials);
    GetSession(keyword, pin, password);
    maid = session_.passport().template Get<Maid>(true);
    Pmid pmid(session_.passport().template Get<Pmid>(true));
    pmid_name = PublicPmid::Name(pmid.name());
    report_progress(kLogin, kJoiningNetwork);
    JoinNetwork(maid);
    report_progress(kLogin, kInitialisingClientComponents);
    storage_.reset(
        new Storage(routing_handler_->asio_service(), routing_handler_->routing(), pmid_name));
    report_progress(kLogin, kStartingVault);
    client_controller_->StartVault(pmid, maid.name(), session_.storage_path());
    session_.set_keyword_pin_password(keyword, pin, password);
  }
  catch (const std::exception& e) {
    // client_controller_->StopVault(); get params!!!!!!!!!
    storage_.reset();
    boost::throw_exception(e);
  }
  return;
}

void ClientMaid::LogOut() {
  //  client_controller_->StopVault(  );  parameters???
  UnMountDrive();
}

void ClientMaid::MountDrive() {
  user_storage_.MountDrive(storage_, session_, slots_.on_service_added);
}

void ClientMaid::UnMountDrive() { user_storage_.UnMountDrive(); }

void ClientMaid::ChangeKeyword(const Keyword& old_keyword, const Keyword& new_keyword,
                               const Pin& pin, const Password& password,
                               ReportProgressFunction& report_progress) {
  report_progress(kChangeKeyword, kStoringUserCredentials);
  PutSession(new_keyword, pin, password);
  DeleteSession(old_keyword, pin);
  session_.set_keyword(new_keyword);
}

void ClientMaid::ChangePin(const Keyword& keyword, const Pin& old_pin, const Pin& new_pin,
                           const Password& password, ReportProgressFunction& report_progress) {
  report_progress(kChangePin, kStoringUserCredentials);
  PutSession(keyword, new_pin, password);
  DeleteSession(keyword, old_pin);
  session_.set_pin(new_pin);
}

void ClientMaid::ChangePassword(const Keyword& keyword, const Pin& pin,
                                const Password& new_password,
                                ReportProgressFunction& report_progress) {
  report_progress(kChangePassword, kStoringUserCredentials);
  PutSession(keyword, pin, new_password);
  session_.set_password(new_password);
}

boost::filesystem::path ClientMaid::mount_path() { return user_storage_.mount_path(); }

boost::filesystem::path ClientMaid::owner_path() { return user_storage_.owner_path(); }

const Slots& ClientMaid::CheckSlots(const Slots& slots) {
  if (!slots.update_available)
    ThrowError(CommonErrors::uninitialised);
  if (!slots.network_health)
    ThrowError(CommonErrors::uninitialised);
  if (!slots.operations_pending)
    ThrowError(CommonErrors::uninitialised);
  return slots;
}

void ClientMaid::PutSession(const Keyword& keyword, const Pin& pin, const Password& password) {
  NonEmptyString serialised_session(session_.Serialise());
  passport::EncryptedSession encrypted_session(
      passport::EncryptSession(keyword, pin, password, serialised_session));
  Tmid tmid(encrypted_session, session_.passport().template Get<Antmid>(true));
  passport::EncryptedTmidName encrypted_tmid_name(
      passport::EncryptTmidName(keyword, pin, tmid.name()));
  Mid::Name mid_name(passport::MidName(keyword, pin));
  Mid mid(mid_name, encrypted_tmid_name, session_.passport().template Get<Anmid>(true));
  PutFob<Tmid>(tmid);
  PutFob<Mid>(mid);
}

void ClientMaid::DeleteSession(const Keyword& keyword, const Pin& pin) {
  Mid::Name mid_name(Mid::GenerateName(keyword, pin));
  auto mid_future(storage_->Get<Mid>(mid_name));
  Mid mid(mid_future.get());
  passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
  Tmid::Name tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
  DeleteFob<Tmid>(tmid_name);
  DeleteFob<Mid>(mid_name);
}

void ClientMaid::GetSession(const Keyword& keyword, const Pin& pin, const Password& password) {
  Mid::Name mid_name(Mid::GenerateName(keyword, pin));
  auto mid_future(storage_->Get<Mid>(mid_name));
  Mid mid(mid_future.get());
  passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
  Tmid::Name tmid_name(passport::DecryptTmidName(keyword, pin, encrypted_tmid_name));
  auto tmid_future(storage_->Get<Tmid>(tmid_name));
  Tmid tmid(tmid_future.get());
  passport::EncryptedSession encrypted_session(tmid.encrypted_session());
  NonEmptyString serialised_session(
      passport::DecryptSession(keyword, pin, password, encrypted_session));
  session_.Parse(serialised_session);
  session_.set_initialised();
}

void ClientMaid::JoinNetwork(const Maid& maid) {
  PublicKeyRequestFunction public_key_request([this](
      const NodeId & node_id,
      const GivePublicKeyFunctor & give_key) { PublicKeyRequest(node_id, give_key); });
  routing_handler_.reset(new RoutingHandler(maid, public_key_request));

  std::vector<boost::asio::ip::udp::endpoint> bootstrap_endpoints;
  client_controller_->GetBootstrapNodes(bootstrap_endpoints);
  EndPointVector endpoints;
  for (auto& endpoint : bootstrap_endpoints)
    endpoints.push_back(std::make_pair(endpoint.address().to_string(), endpoint.port()));

  routing_handler_->Join(endpoints);
}

void ClientMaid::RegisterPmid(const Maid& maid, const Pmid& pmid) {
  PmidRegistration pmid_registration(maid, pmid, false);
  storage_->RegisterPmid(pmid_registration);
}

void ClientMaid::UnregisterPmid(const Maid& maid, const Pmid& pmid) {
  PmidRegistration pmid_unregistration(maid, pmid, true);
  storage_->UnregisterPmid(pmid_unregistration);
}

void ClientMaid::UnCreateUser(bool fobs_confirmed, bool drive_mounted) {
  if (fobs_confirmed) {
    Maid maid(session_.passport().template Get<Maid>(fobs_confirmed));
    Pmid pmid(session_.passport().template Get<Pmid>(fobs_confirmed));
    UnregisterPmid(maid, pmid);
  }
  // client_controller_->StopVault(); get params!!!!!!!!!
  if (drive_mounted)
    try {
      UnMountDrive();
    }
  catch (...) {/* consume exception */
  }
  storage_.reset();
}

template <typename Fob>
void ClientMaid::PutFob(const Fob& fob) {
  storage_->Put<Fob>(fob);
}

template <typename Fob>
void ClientMaid::DeleteFob(const typename Fob::Name& fob_name) {
  storage_->Delete<Fob>(fob_name);
}

template <typename Fob>
Fob ClientMaid::GetFob(const typename Fob::Name& fob_name) {
  std::future<Fob> fob_future(storage_->Get<Fob>(fob_name));
  return fob_future.get();
}

void ClientMaid::PutFreeFobs() {
  PublicAnmaid public_anmaid(session_.passport().template Get<Anmaid>(false));
  PublicMaid public_maid(session_.passport().template Get<Maid>(false));
  PublicPmid public_pmid(session_.passport().template Get<Pmid>(false));

  storage_->Put<PublicAnmaid>(public_anmaid);
  storage_->Put<PublicMaid>(public_maid);
  storage_->Put<PublicPmid>(public_pmid);
}

void ClientMaid::PutPaidFobs() {
  PublicAnmid public_anmid(session_.passport().template Get<Anmid>(true));
  PublicAnsmid public_ansmid(session_.passport().template Get<Ansmid>(true));
  PublicAntmid public_antmid(session_.passport().template Get<Antmid>(true));

  storage_->Put<PublicAnmid>(public_anmid);
  storage_->Put<PublicAnsmid>(public_ansmid);
  storage_->Put<PublicAntmid>(public_antmid);
}

void ClientMaid::PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key) {
  if (storage_) {
    typedef passport::PublicPmid PublicPmid;
    PublicPmid::Name pmid_name(Identity(node_id.string()));
    auto pmid_future(storage_->Get<PublicPmid>(pmid_name));
    give_key(pmid_future.get().public_key());
  } else {
    ThrowError(CommonErrors::uninitialised);
  }
}

}  // lifestuff
}  // maidsafe
