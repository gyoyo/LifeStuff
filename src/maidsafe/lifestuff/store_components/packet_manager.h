/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Interface allowing storage of data to network or local database
* Version:      1.0
* Created:      2009-01-29-00.49.17
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_PACKET_MANAGER_H_
#define MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_PACKET_MANAGER_H_

#include <functional>
#include <string>
#include <vector>

#include "maidsafe/lifestuff/maidsafe.h"
#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 110
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace maidsafe {

class ChunkStore;

namespace lifestuff {

enum IfPacketExists {
  kDoNothingReturnFailure,
  kDoNothingReturnSuccess,
  kOverwrite,
  kAppend
};

typedef std::function<void(const std::vector<std::string>&, int)>
        GetPacketFunctor;

class PacketManager {
 public:
  virtual ~PacketManager() {}

  virtual void Init(VoidFuncOneInt callback) = 0;

  virtual int Close(bool cancel_pending_ops) = 0;

  virtual bool KeyUnique(const std::string &key) = 0;

  virtual void KeyUnique(const std::string &key,
                         const VoidFuncOneInt &cb) = 0;

  virtual int GetPacket(const std::string &packet_name,
                        std::vector<std::string> *results) = 0;

  virtual void GetPacket(const std::string &packet_name,
                         const GetPacketFunctor &cb) = 0;

  virtual void StorePacket(const std::string &packet_name,
                           const std::string &value,
                           const VoidFuncOneInt &cb) = 0;

  virtual void DeletePacket(const std::string &packet_name,
                            const std::string &value,
                            const VoidFuncOneInt &cb) = 0;

  virtual void UpdatePacket(const std::string &packet_name,
                            const std::string &old_value,
                            const std::string &new_value,
                            const VoidFuncOneInt &cb) = 0;

  virtual std::shared_ptr<ChunkStore> chunk_store() const = 0;

 protected:
  PacketManager() {}

 private:
  PacketManager(const PacketManager&);
  PacketManager& operator=(const PacketManager&);
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_PACKET_MANAGER_H_