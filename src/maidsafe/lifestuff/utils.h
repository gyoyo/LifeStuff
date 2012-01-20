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

#ifndef MAIDSAFE_LIFESTUFF_UTILS_H_
#define MAIDSAFE_LIFESTUFF_UTILS_H_

#include <memory>
#include <string>

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/rsa.h"

#include "maidsafe/pki/packet.h"

namespace maidsafe {

namespace lifestuff {

class PacketManager;

int GetValidatedMpidPublicKey(const std::string &public_username,
                              const std::string &own_mpid_name,
                              std::shared_ptr<PacketManager> packet_manager,
                              asymm::PublicKey *public_key);

int GetValidatedMmidPublicKey(const std::string &mmid_name,
                              const std::string &own_mmid_name,
                              std::shared_ptr<PacketManager> packet_manager,
                              asymm::PublicKey *public_key);

void SendContactInfoCallback(const int &response,
                             boost::mutex *mutex,
                             boost::condition_variable *cond_var,
                             int *result);

int AwaitingResponse(boost::mutex &mutex,
                     boost::condition_variable &cond_var,
                     std::vector<int> &results);

std::string ComposeSignaturePacketName(const std::string &name);

std::string ComposeSignaturePacketValue(
    const maidsafe::pki::SignaturePacket &packet);
}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_UTILS_H_
