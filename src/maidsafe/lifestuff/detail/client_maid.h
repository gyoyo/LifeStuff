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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_

#include "maidsafe/data_store/sure_file_store.h"

#include "maidsafe/nfs/client/maid_node_nfs.h"
#include "maidsafe/nfs/vault/pmid_registration.h"
#include "maidsafe/routing/routing_api.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff_manager/client_controller.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_storage.h"
#include "maidsafe/lifestuff/detail/routing_handler.h"

namespace maidsafe {
namespace lifestuff {

class ClientMaid {
 public:
  typedef std::unique_ptr<RoutingHandler> RoutingHandlerPtr;
  typedef RoutingHandler::EndPointVector EndPointVector;
  typedef nfs_vault::PmidRegistration PmidRegistration;
  typedef lifestuff_manager::ClientController ClientController;
  typedef std::unique_ptr<ClientController> ClientControllerPtr;
  typedef nfs_client::MaidNodeNfs Storage;
  typedef std::shared_ptr<Storage> StoragePtr;
  typedef UserStorage UserStorage;
  typedef passport::Passport Passport;
  typedef passport::Anmid Anmid;
  typedef passport::Ansmid Ansmid;
  typedef passport::Antmid Antmid;
  typedef passport::Anmaid Anmaid;
  typedef passport::Maid Maid;
  typedef passport::Pmid Pmid;
  typedef passport::Mid Mid;
  typedef passport::Tmid Tmid;
  typedef passport::PublicAnmid PublicAnmid;
  typedef passport::PublicAnsmid PublicAnsmid;
  typedef passport::PublicAntmid PublicAntmid;
  typedef passport::PublicAnmaid PublicAnmaid;
  typedef passport::PublicMaid PublicMaid;
  typedef passport::PublicPmid PublicPmid;

  ClientMaid(Session& session, const Slots& slots);
  ~ClientMaid();

  void CreateUser(const Keyword& keyword,
                  const Pin& pin,
                  const Password& password,
                  const boost::filesystem::path& storage_path,
                  ReportProgressFunction& report_progress);
  void LogIn(const Keyword& keyword,
             const Pin& pin,
             const Password& password,
             const boost::filesystem::path& storage_path,
             ReportProgressFunction& report_progress);
  void LogOut();

  void MountDrive();
  void UnMountDrive();

  void ChangeKeyword(const Keyword& old_keyword,
                     const Keyword& new_keyword,
                     const Pin& pin,
                     const Password& password,
                     ReportProgressFunction& report_progress);
  void ChangePin(const Keyword& keyword,
                 const Pin& old_pin,
                 const Pin& new_pin,
                 const Password& password,
                 ReportProgressFunction& report_progress);
  void ChangePassword(const Keyword& keyword,
                      const Pin& pin,
                      const Password& new_password,
                      ReportProgressFunction& report_progress);

  boost::filesystem::path mount_path();
  boost::filesystem::path owner_path();

 private:

  const Slots& CheckSlots(const Slots& slots);

  void PutSession(const Keyword& keyword, const Pin& pin, const Password& password);
  void DeleteSession(const Keyword& keyword, const Pin& pin);
  void GetSession(const Keyword& keyword, const Pin& pin, const Password& password);

  void JoinNetwork(const Maid& maid);

  void RegisterPmid(const Maid& maid, const Pmid& pmid);
  void UnregisterPmid(const Maid& maid, const Pmid& pmid);

  void UnCreateUser(bool fobs_confirmed, bool drive_mounted);

  template<typename Fob> void PutFob(const Fob& fob);
  template<typename Fob> void DeleteFob(const typename Fob::Name& fob_name);
  template<typename Fob> Fob GetFob(const typename Fob::Name& fob_name);
  
  void PutFreeFobs();
  void PutPaidFobs();

  void PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key);

  Slots slots_;
  Session& session_;
  ClientControllerPtr client_controller_;
  StoragePtr storage_;
  UserStorage user_storage_;
  RoutingHandlerPtr routing_handler_;
};

}  // lifestuff
}  // maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_
