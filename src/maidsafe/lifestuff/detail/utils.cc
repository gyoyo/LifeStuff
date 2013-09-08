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

#include "maidsafe/lifestuff/detail/utils.h"

namespace maidsafe {
namespace lifestuff {

namespace detail {
  template <>
  struct PutFobs<Free> {
    typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
    typedef passport::Passport Passport;
    typedef passport::Anmaid Anmaid;
    typedef passport::PublicAnmaid PublicAnmaid;
    typedef passport::Maid Maid;
    typedef passport::PublicMaid PublicMaid;
    typedef passport::Pmid Pmid;
    typedef passport::PublicPmid PublicPmid;

    void operator()(ClientNfs& client_nfs, Passport& passport, ReplyFunction& reply) {
      Pmid::Name pmid_name(passport.Get<Pmid>(false).name());
      PublicAnmaid public_anmaid(passport.Get<Anmaid>(false));
      PublicMaid public_maid(passport.Get<Maid>(false));
      PublicPmid public_pmid(passport.Get<Pmid>(false));

      maidsafe::nfs::Put<PublicAnmaid>(client_nfs, public_anmaid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicMaid>(client_nfs, public_maid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicPmid>(client_nfs, public_pmid, pmid_name, 3, reply);
    }
  };

  template <>
  struct PutFobs<Paid> {
    typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
    typedef passport::Passport Passport;
    typedef passport::Anmid Anmid;
    typedef passport::PublicAnmid PublicAnmid;
    typedef passport::Ansmid Ansmid;
    typedef passport::PublicAnsmid PublicAnsmid;
    typedef passport::Antmid Antmid;
    typedef passport::PublicAntmid PublicAntmid;
    typedef passport::Pmid Pmid;

    void operator()(ClientNfs& client_nfs, Passport& passport, ReplyFunction& reply) {
      Pmid::Name pmid_name(passport.Get<Pmid>(true).name());
      PublicAnmid public_anmid(passport.Get<Anmid>(true));
      PublicAnsmid public_ansmid(passport.Get<Ansmid>(true));
      PublicAntmid public_antmid(passport.Get<Antmid>(true));

      maidsafe::nfs::Put<PublicAnmid>(client_nfs, public_anmid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicAnsmid>(client_nfs, public_ansmid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicAntmid>(client_nfs, public_antmid, pmid_name, 3, reply);
    }
  };
}  // namespace detail

}  // namespace lifestuff
}  // namespace maidsafe
