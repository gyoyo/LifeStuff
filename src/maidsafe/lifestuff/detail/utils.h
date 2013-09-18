/*  Copyright 2011 MaidSafe.net limited

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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_

#include "maidsafe/passport/passport.h"
#include "maidsafe/lifestuff/detail/session.h"

namespace maidsafe {
namespace lifestuff {

// typedef std::function<void(maidsafe::nfs::Reply)> ReplyFunction;

struct Free;
struct Paid;

namespace detail {

  template <typename Duty>
  struct PutFobs {
    typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
    typedef passport::Passport Passport;

    void operator()(ClientNfs&, Passport&/*, ReplyFunction&*/) {}
  };

  template <typename Input>
  struct InsertUserInput {
    typedef std::unique_ptr<Input> InputPtr;

    void operator()(InputPtr& input, uint32_t position, const std::string& characters) {
      if (!input)
        input.reset(new Input());
      input->Insert(position, characters);
      return;
    }
  };

  template <typename Input>
  struct RemoveUserInput {
    typedef std::unique_ptr<Input> InputPtr;

    void operator()(InputPtr& input, uint32_t position, uint32_t length) {
      if (!input)
        ThrowError(CommonErrors::uninitialised);
      input->Remove(position, length);
      return;
    }
  };

  template <typename Input>
  struct ClearUserInput {
    typedef std::unique_ptr<Input> InputPtr;

    void operator()(InputPtr& input) {
      if (input)
        input->Clear();
      return;
    }
  };

  template <typename Input>
  struct ConfirmUserInput {
    typedef std::unique_ptr<Input> InputPtr;

     bool operator()(InputPtr& input) {
      if (!input)
        return false;
      return input->IsValid(boost::regex(kCharRegex));
    }

    bool operator()(InputPtr& input, InputPtr& confirmation_input) {
      if (!input || !confirmation_input)
        return false;
      if (!input->IsFinalised())
        input->Finalise();
      if (!confirmation_input->IsFinalised())
        confirmation_input->Finalise();
      if (input->string() != confirmation_input->string()) {
        return false;
      }
      return true;
    }

    bool operator()(InputPtr& input, InputPtr& confirmation_input, InputPtr& current_input, const Session& session) {
      if (!current_input)
        return false;
      if (!current_input->IsFinalised())
        current_input->Finalise();
      if (input) {
        input->Finalise();
        if (!confirmation_input)
          return false;
        confirmation_input->Finalise();
        if (input->string() != confirmation_input->string()
            || session.password().string() != current_input->string())
          return false;
      } else {
        if (session.password().string() != current_input->string())
          return false;
      }
      return true;
    }
  };

}  // namespace detail

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_UTILS_H_
