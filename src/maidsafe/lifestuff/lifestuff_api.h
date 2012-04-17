/*
* ============================================================================
*
* Copyright [2012] maidsafe.net limited
*
* Description:  Definition of system-wide constants/enums/structs
* Version:      1.0
* Created:      2012-03-27
* Revision:     none
* Compiler:     gcc
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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_

#include <map>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/drive/drive_api.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 400
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace fs = boost::filesystem;
namespace maidsafe {

namespace lifestuff {

class LifeStuff {
 public:
  LifeStuff();
  ~LifeStuff();

  /// State operations
  int Initialise(const fs::path &base_directory = fs::path());
  int ConnectToSignals(
      const ChatFunction &chat_slot,
      const FileTransferFunction &file_slot,
      const NewContactFunction &new_contact_slot,
      const ContactConfirmationFunction &confirmed_contact_slot,
      const ContactProfilePictureFunction &profile_picture_slot,
      const ContactPresenceFunction &contact_presence_slot,
      const ContactDeletionFunction &contact_deletion_function,
      const ShareInvitationFunction &share_invitation_function,
      const ShareDeletionFunction &share_deletion_function,
      const MemberAccessLevelFunction &access_level_function);
  int Finalise();

  /// Credential operations
  int CreateUser(const std::string &username,
                 const std::string &pin,
                 const std::string &password);
  int CreatePublicId(const std::string &public_id);
  int LogIn(const std::string &username,
            const std::string &pin,
            const std::string &password);
  int LogOut();

  /// Contact operations
  int AddContact(const std::string &my_public_id,
                 const std::string &contact_public_id);
  int ConfirmContact(const std::string &my_public_id,
                     const std::string &contact_public_id);
  int DeclineContact(const std::string &my_public_id,
                     const std::string &contact_public_id);
  int RemoveContact(const std::string &my_public_id,
                    const std::string &contact_public_id,
                    const std::string &removal_message);
  int ChangeProfilePicture(const std::string &my_public_id,
                           const std::string &profile_picture_contents);
  std::string GetOwnProfilePicture(const std::string &my_public_id);
  std::string GetContactProfilePicture(const std::string &my_public_id,
                                       const std::string &contact_public_id);
  ContactMap GetContacts(const std::string &my_public_id,
                         uint16_t bitwise_status = kConfirmed | kRequestSent);
  std::vector<std::string> PublicIdsList() const;

  /// Messaging
  int SendChatMessage(const std::string &sender_public_id,
                      const std::string &receiver_public_id,
                      const std::string &message);
  int SendFile(const std::string &sender_public_id,
               const std::string &receiver_public_id,
               const fs::path absolute_path);
  int AcceptSentFile(const fs::path absolute_path,
                     const std::string &identifier);
  int RejectSentFile(const std::string &identifier);

  /// Filesystem
  int ReadHiddenFile(const fs::path &absolute_path, std::string *content) const;
  int WriteHiddenFile(const fs::path &absolute_path,
                      const std::string &content,
                      bool overwrite_existing);
  int DeleteHiddenFile(const fs::path &absolute_path);

  /// Private Shares
  // If error code is given, map of rsults should be empty. If nobody added,
  // revert everything. Directory has to be moved, not copied. If directory
  // already exists in shared stuff, append ending as dropbox does. If a
  // contact is passed in as owner, it should fail for that contact.
  int CreatePrivateShareFromExistingDirectory(
      const std::string &my_public_id,
      const fs::path &directory_in_lifestuff_drive,
      const StringIntMap &contacts,
      std::string *share_name,
      StringIntMap *results);
  int CreateEmptyPrivateShare(const std::string &my_public_id,
                              const StringIntMap &contacts,
                              std::string *share_name,
                              StringIntMap *results);
  int GetPrivateShareList(const std::string &my_public_id,
                          StringIntMap *shares_names);
  // For owners only
  int GetPrivateShareMemebers(const std::string &my_public_id,
                              const std::string &share_name,
                              StringIntMap *shares_members);
  int GetPrivateSharesIncludingMember(const std::string &my_public_id,
                                      const std::string &contact_public_id,
                                      std::vector<std::string> *shares_names);
  // Should create a directory adapting to other possible shares
  int AcceptPrivateShareInvitation(std::string *share_name,
                                   const std::string &my_public_id,
                                   const std::string &contact_public_id,
                                   const std::string &share_id);
  int RejectPrivateShareInvitation(const std::string &my_public_id,
                                   const std::string &share_id);
  // Only for owners
  int EditPrivateShareMembers(const std::string &my_public_id,
                              const StringIntMap &public_ids,
                              const std::string &share_name,
                              StringIntMap *results);
  // Only for owners
  int DeletePrivateShare(const std::string &my_public_id,
                         const std::string &share_name);
  // Should work for RO and full access. Only for non-owners
  int LeavePrivateShare(const std::string &my_public_id,
                        const std::string &share_name);

  ///
  int state() const;
  fs::path mount_path() const;

 private:
  struct Elements;
  std::shared_ptr<Elements> lifestuff_elements;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_