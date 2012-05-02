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

#include "maidsafe/lifestuff/lifestuff_api.h"

#include <algorithm>
#include <functional>
#include <vector>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/data_map.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/message_handler.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/user_credentials.h"
#include "maidsafe/lifestuff/user_storage.h"
#include "maidsafe/lifestuff/utils.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff {

struct LifeStuff::Elements {
  Elements() : thread_count(kThreads),
               state(kZeroth),
               buffered_path(),
#ifdef LOCAL_TARGETS_ONLY
               simulation_path(),
#endif
               interval(kSecondsInterval),
               asio_service(),
               remote_chunk_store(),
#ifndef LOCAL_TARGETS_ONLY
               client_container(),
#endif
               session(),
               user_credentials(),
               user_storage(),
               public_id(),
               message_handler() {}

  int thread_count;
  LifeStuffState state;
  fs::path buffered_path;
#ifdef LOCAL_TARGETS_ONLY
  fs::path simulation_path;
#endif
  bptime::seconds interval;
  AsioService asio_service;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store;
#ifndef LOCAL_TARGETS_ONLY
  std::shared_ptr<pd::ClientContainer> client_container;
#endif
  std::shared_ptr<Session> session;
  std::shared_ptr<UserCredentials> user_credentials;
  std::shared_ptr<UserStorage> user_storage;
  std::shared_ptr<PublicId> public_id;
  std::shared_ptr<MessageHandler> message_handler;
};

LifeStuff::LifeStuff() : lifestuff_elements(new Elements) {}

LifeStuff::~LifeStuff() {}

int LifeStuff::Initialise(const boost::filesystem::path &base_directory) {
  if (lifestuff_elements->state != kZeroth) {
    DLOG(ERROR) << "Make sure that object is in the original Zeroth state. "
                << "Asimov rules.";
    return kGeneralError;
  }

  // Initialisation
  lifestuff_elements->asio_service.Start(lifestuff_elements->thread_count);
  lifestuff_elements->session.reset(new Session);

  fs::path base_path, buffered_chunk_store_path, network_simulation_path;
  if (base_directory.empty()) {
    // Not a test: everything in $HOME/.lifestuff
    base_path = GetHomeDir() / kAppHomeDirectory;
    buffered_chunk_store_path = base_path / RandomAlphaNumericString(16);
    boost::system::error_code error_code;
    network_simulation_path = fs::temp_directory_path(error_code) /
                              "lifestuff_simulation";
  } else {
    // Presumably a test
    base_path = base_directory;
    buffered_chunk_store_path = base_path / RandomAlphaNumericString(16);
    network_simulation_path = base_path / "simulated_network";
  }

#ifdef LOCAL_TARGETS_ONLY
  lifestuff_elements->remote_chunk_store =
      BuildChunkStore(buffered_chunk_store_path,
                      network_simulation_path,
                      lifestuff_elements->asio_service.service());
  lifestuff_elements->simulation_path = network_simulation_path;
#else
  lifestuff_elements->remote_chunk_store =
      BuildChunkStore(buffered_chunk_store_path,
                      &lifestuff_elements->client_container);
#endif
  lifestuff_elements->buffered_path = buffered_chunk_store_path;

  lifestuff_elements->user_credentials.reset(
      new UserCredentials(lifestuff_elements->remote_chunk_store,
                          lifestuff_elements->session));

  lifestuff_elements->public_id.reset(
      new PublicId(lifestuff_elements->remote_chunk_store,
                   lifestuff_elements->session,
                   lifestuff_elements->asio_service.service()));

  lifestuff_elements->message_handler.reset(
      new MessageHandler(lifestuff_elements->remote_chunk_store,
                         lifestuff_elements->session,
                         lifestuff_elements->asio_service.service()));

  lifestuff_elements->user_storage.reset(
      new UserStorage(lifestuff_elements->remote_chunk_store,
                      lifestuff_elements->message_handler));

  lifestuff_elements->message_handler->ConnectToParseAndSaveDataMapSignal(
      std::bind(&UserStorage::ParseAndSaveDataMap,
                lifestuff_elements->user_storage,
                args::_1, args::_2, args::_3));

  lifestuff_elements->message_handler->ConnectToSaveShareDataSignal(
      std::bind(&UserStorage::SaveShareData,
                lifestuff_elements->user_storage, args::_1, args::_2));

  lifestuff_elements->message_handler->ConnectToShareUserLeavingSignal(
      std::bind(&UserStorage::UserLeavingShare,
                lifestuff_elements->user_storage, args::_1, args::_2));

  lifestuff_elements->message_handler->ConnectToShareDeletionSignal(
      std::bind(&UserStorage::LeaveShare,
                lifestuff_elements->user_storage, args::_1, args::_2));

  lifestuff_elements->message_handler->ConnectToShareUpdateSignal(
      std::bind(&UserStorage::UpdateShare,
                lifestuff_elements->user_storage, args::_1, args::_2,
                                                  args::_3, args::_4));

  lifestuff_elements->message_handler->ConnectToMemberAccessLevelSignal(
      std::bind(&UserStorage::MemberAccessChange,
                lifestuff_elements->user_storage, args::_1, args::_2,
                                                  args::_3, args::_4));

  lifestuff_elements->public_id->ConnectToContactConfirmedSignal(
      std::bind(&MessageHandler::InformConfirmedContactOnline,
                lifestuff_elements->message_handler, args::_1, args::_2));


  lifestuff_elements->message_handler->ConnectToContactDeletionSignal(
      std::bind(&PublicId::RemoveContactHandle,
                lifestuff_elements->public_id, args::_1, args::_2));

  lifestuff_elements->state = kInitialised;

  return kSuccess;
}

int LifeStuff::ConnectToSignals(
    const ChatFunction &chat_slot,
    const FileTransferFunction &file_slot,
    const NewContactFunction &new_contact_slot,
    const ContactConfirmationFunction &confirmed_contact_slot,
    const ContactProfilePictureFunction &profile_picture_slot,
    const ContactPresenceFunction &contact_presence_slot,
    const ContactDeletionFunction &contact_deletion_function,
    const ShareInvitationFunction &share_invitation_function,
    const ShareDeletionFunction &share_deletion_function,
    const MemberAccessLevelFunction &access_level_function) {
  if (lifestuff_elements->state != kInitialised) {
    DLOG(ERROR) << "Make sure that object is initialised";
    return kGeneralError;
  }

  int connects(0);
  if (chat_slot) {
    lifestuff_elements->message_handler->ConnectToChatSignal(chat_slot);
    ++connects;
  }
  if (file_slot) {
    lifestuff_elements->message_handler->ConnectToFileTransferSignal(file_slot);
    ++connects;
  }
  if (new_contact_slot) {
    lifestuff_elements->public_id->ConnectToNewContactSignal(new_contact_slot);
    ++connects;
  }
  if (confirmed_contact_slot) {
    lifestuff_elements->public_id->ConnectToContactConfirmedSignal(
        confirmed_contact_slot);
    ++connects;
  }
  if (profile_picture_slot) {
    lifestuff_elements->message_handler->ConnectToContactProfilePictureSignal(
        profile_picture_slot);
    ++connects;
  }
  if (contact_presence_slot) {
    lifestuff_elements->message_handler->ConnectToContactPresenceSignal(
        contact_presence_slot);
    ++connects;
  }
  if (contact_deletion_function) {
    lifestuff_elements->message_handler->ConnectToContactDeletionSignal(
        contact_deletion_function);
    ++connects;
  }
  if (share_invitation_function) {
    lifestuff_elements->message_handler->ConnectToShareInvitationSignal(
        share_invitation_function);
    ++connects;
  }
  if (share_deletion_function) {
    lifestuff_elements->message_handler->ConnectToShareDeletionSignal(
        share_deletion_function);
    ++connects;
  }
  if (access_level_function) {
    lifestuff_elements->message_handler->ConnectToMemberAccessLevelSignal(
        access_level_function);
    ++connects;
  }

  if (connects > 0) {
    lifestuff_elements->state = kConnected;
    return kSuccess;
  }

  return kGeneralError;
}

int LifeStuff::Finalise() {
  if (lifestuff_elements->state != kLoggedOut) {
    DLOG(ERROR) << "Need to be logged out to finalise.";
    return kGeneralError;
  }

  boost::system::error_code error_code;
  fs::remove_all(lifestuff_elements->buffered_path, error_code);


  lifestuff_elements->asio_service.Stop();
  lifestuff_elements->remote_chunk_store.reset();
#ifndef LOCAL_TARGETS_ONLY
  lifestuff_elements->client_container.reset();
#endif
  lifestuff_elements->message_handler.reset();
  lifestuff_elements->public_id.reset();
  lifestuff_elements->session.reset();
  lifestuff_elements->user_credentials.reset();
  lifestuff_elements->user_storage.reset();
  lifestuff_elements->state = kZeroth;

  return kSuccess;
}

/// Credential operations
int LifeStuff::CreateUser(const std::string &username,
                          const std::string &pin,
                          const std::string &password) {
  if (lifestuff_elements->state != kConnected) {
    DLOG(ERROR) << "Make sure that object is initialised and connected";
    return kGeneralError;
  }

  if (!lifestuff_elements->user_credentials->CreateUser(username,
                                                        pin,
                                                        password)) {
    DLOG(ERROR) << "Failed to Create User.";
    return kGeneralError;
  }

  boost::system::error_code error_code;
  fs::path mount_dir(GetHomeDir() /
                     kAppHomeDirectory /
                     lifestuff_elements->session->session_name());
  if (!fs::exists(mount_dir, error_code)) {
    fs::create_directories(mount_dir, error_code);
    if (error_code) {
      DLOG(ERROR) << "Failed to create app directories - " << error_code.value()
                  << ": " << error_code.message();
      return kGeneralError;
    }
  }

  lifestuff_elements->user_storage->MountDrive(mount_dir,
                                               lifestuff_elements->session,
                                               true);
  if (!lifestuff_elements->user_storage->mount_status()) {
    DLOG(ERROR) << "Failed to mount";
    return kGeneralError;
  }

  fs::create_directories(lifestuff_elements->user_storage->mount_dir() /
                             fs::path("/").make_preferred() /
                             kMyStuff / kDownloadStuff,
                         error_code);
  if (error_code) {
    DLOG(ERROR) << "Failed creating My Stuff: " << error_code.message();
    return kGeneralError;
  }
  fs::create_directory(lifestuff_elements->user_storage->mount_dir() /
                           fs::path("/").make_preferred() / kSharedStuff,
                       error_code);
  if (error_code) {
    DLOG(ERROR) << "Failed creating Shared Stuff: " << error_code.message();
    return kGeneralError;
  }

  int result(lifestuff_elements->user_credentials->SaveSession());
  if (result != kSuccess) {
    DLOG(WARNING) << "Failed to save session.";
  }

  lifestuff_elements->state = kLoggedIn;

  return kSuccess;
}

int LifeStuff::CreatePublicId(const std::string &public_id) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state to create a public ID.";
    return kGeneralError;
  }

  // Check if it's the 1st one
  bool first_public_id(false);
  if (lifestuff_elements->session->contact_handler_map().empty())
    first_public_id = true;

  int result(lifestuff_elements->public_id->CreatePublicId(public_id, true));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create public ID.";
    return result;
  }

  if (first_public_id) {
    lifestuff_elements->public_id->StartCheckingForNewContacts(
        lifestuff_elements->interval);
    lifestuff_elements->message_handler->StartUp(
        lifestuff_elements->interval);
  }

  return kSuccess;
}

int LifeStuff::LogIn(const std::string &username,
                     const std::string &pin,
                     const std::string &password) {
  if (!(lifestuff_elements->state == kConnected ||
        lifestuff_elements->state == kLoggedOut)) {
    DLOG(ERROR) << "Make sure that object is initialised and connected";
    return kGeneralError;
  }

  int result(lifestuff_elements->user_credentials->CheckUserExists(username,
                                                                   pin));
  if (result != kUserExists) {
    DLOG(ERROR) << "User doesn't exist.";
    return result;
  }

  if (!lifestuff_elements->user_credentials->ValidateUser(password)) {
    DLOG(ERROR) << "Wrong password.";
    return kGeneralError;
  }

  boost::system::error_code error_code;
  fs::path mount_dir(GetHomeDir() /
                     kAppHomeDirectory /
                     lifestuff_elements->session->session_name());
  if (!fs::exists(mount_dir, error_code)) {
    fs::create_directories(mount_dir, error_code);
    if (error_code) {
      DLOG(ERROR) << "Failed to create app directories - " << error_code.value()
                  << ": " << error_code.message();
      return kGeneralError;
    }
  }

  lifestuff_elements->user_storage->MountDrive(mount_dir,
                                               lifestuff_elements->session,
                                               false);

  if (!lifestuff_elements->user_storage->mount_status()) {
    DLOG(ERROR) << "Failed to mount";
    return kGeneralError;
  }

  if (!lifestuff_elements->session->contact_handler_map().empty()) {
    lifestuff_elements->public_id->StartUp(lifestuff_elements->interval);
    lifestuff_elements->message_handler->StartUp(lifestuff_elements->interval);
  }

  lifestuff_elements->state = kLoggedIn;

  return kSuccess;
}

int LifeStuff::LogOut() {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  lifestuff_elements->user_storage->UnMountDrive();
  if (lifestuff_elements->user_storage->mount_status()) {
    DLOG(ERROR) << "Failed to un-mount.";
    return kGeneralError;
  }

  lifestuff_elements->public_id->ShutDown();
  lifestuff_elements->message_handler->ShutDown();

  if (!lifestuff_elements->user_credentials->Logout()) {
    DLOG(ERROR) << "Failed to log out.";
    return kGeneralError;
  }

  if (!lifestuff_elements->remote_chunk_store->WaitForCompletion()) {
    DLOG(ERROR) << "Failed complete chunk operations.";
    return kGeneralError;
  }

  // Delete mount directory
  boost::system::error_code error_code;
  fs::remove_all(lifestuff_elements->user_storage->mount_dir(), error_code);
  if (error_code)
    DLOG(WARNING) << "Failed to delete mount directory: "
                  << lifestuff_elements->user_storage->mount_dir();
  lifestuff_elements->session->Reset();

  lifestuff_elements->state = kLoggedOut;

  return kSuccess;
}

int LifeStuff::CheckPassword(const std::string &password) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  return lifestuff_elements->session->password() == password ? kSuccess :
                                                               kGeneralError;
}

int LifeStuff::ChangeKeyword(const std::string &old_username,
                             const std::string &new_username,
                             const std::string &password) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  int result(CheckPassword(password));
  if (result != kSuccess) {
    DLOG(ERROR) << "Password verification failed.";
    return result;
  }

  if (lifestuff_elements->session->username() != old_username) {
    DLOG(ERROR) << "Keyword verification failed.";
    return kGeneralError;
  }

  if (old_username.compare(new_username) == 0) {
    DLOG(INFO) << "Same value for old and new.";
    return kSuccess;
  }

  return lifestuff_elements->user_credentials->ChangeUsername(new_username) ?
         kSuccess : kGeneralError;
}

int LifeStuff::ChangePin(const std::string &old_pin,
                         const std::string &new_pin,
                         const std::string &password) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  int result(CheckPassword(password));
  if (result != kSuccess) {
    DLOG(ERROR) << "Password verification failed.";
    return result;
  }

  if (lifestuff_elements->session->pin() != old_pin) {
    DLOG(ERROR) << "Keyword verification failed.";
    return kGeneralError;
  }

  if (old_pin.compare(new_pin) == 0) {
    DLOG(INFO) << "Same value for old and new.";
    return kSuccess;
  }

  return lifestuff_elements->user_credentials->ChangePin(new_pin) ?
         kSuccess : kGeneralError;
}

int LifeStuff::ChangePassword(const std::string &old_password,
                              const std::string &new_password) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  int result(CheckPassword(old_password));
  if (result != kSuccess) {
    DLOG(ERROR) << "Password verification failed.";
    return result;
  }

  if (old_password.compare(new_password) == 0) {
    DLOG(INFO) << "Same value for old and new.";
    return kSuccess;
  }

  return lifestuff_elements->user_credentials->ChangePassword(new_password) ?
         kSuccess : kGeneralError;
}

/// Contact operations
int PreContactChecks(const LifeStuffState &state,
                     const std::string &my_public_id,
                     std::shared_ptr<Session> session) {
  if (state != kLoggedIn) {
    DLOG(ERROR) << "Incorrect state. Should be logged in.";
    return kGeneralError;
  }

  auto it(session->contact_handler_map().find(my_public_id));
  if (it == session->contact_handler_map().end()) {
    DLOG(ERROR) << "No such public ID.";
    return kGeneralError;
  }

  return kSuccess;
}

int LifeStuff::AddContact(const std::string &my_public_id,
                          const std::string &contact_public_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in AddContact.";
    return result;
  }

  return lifestuff_elements->public_id->SendContactInfo(my_public_id,
                                                        contact_public_id,
                                                        true);
}

int LifeStuff::ConfirmContact(const std::string &my_public_id,
                              const std::string &contact_public_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in ConfirmContact.";
    return result;
  }

  result = lifestuff_elements->public_id->ConfirmContact(my_public_id,
                                                         contact_public_id,
                                                         true);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to Confirm Contact.";
    return result;
  }

  return lifestuff_elements->message_handler->SendPresenceMessage(
             my_public_id,
             contact_public_id,
             kOnline);
}

int LifeStuff::DeclineContact(const std::string &my_public_id,
                              const std::string &contact_public_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in DeclineContact.";
    return result;
  }

  return lifestuff_elements->public_id->ConfirmContact(my_public_id,
                                                       contact_public_id,
                                                       false);
}

int LifeStuff::RemoveContact(const std::string &my_public_id,
                             const std::string &contact_public_id,
                             const std::string &removal_message) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in RemoveContact.";
    return result;
  }

  // For private shares, if share_members can be fetched, indicates owner
  // otherwise, only the owner(inviter) of the share can be fetched
  std::vector<std::string> shares_names;
  GetPrivateSharesIncludingMember(my_public_id,
                                  contact_public_id,
                                  &shares_names);
  StringIntMap contact_to_remove;
  contact_to_remove.insert(std::make_pair(contact_public_id, kShareRemover));
  for (auto it = shares_names.begin(); it != shares_names.end(); ++it) {
    StringIntMap results;
    EditPrivateShareMembers(my_public_id, contact_to_remove, *it, &results);
  }
  shares_names.clear();
  lifestuff_elements->user_storage->GetPrivateSharesContactBeingOwner(
                              my_public_id, contact_public_id, &shares_names);
  for (auto it = shares_names.begin(); it != shares_names.end(); ++it) {
    LeavePrivateShare(my_public_id, *it);
  }

  // Send message to removal
  InboxItem inbox_item(kContactDeletion);
  inbox_item.receiver_public_id = contact_public_id;
  inbox_item.sender_public_id = my_public_id;
  inbox_item.content.push_back(removal_message);

  result = lifestuff_elements->message_handler->Send(my_public_id,
                                                     contact_public_id,
                                                     inbox_item);
  if (result != kSuccess)
    DLOG(ERROR) << "Failed in sending out removal message.";

  // Remove the contact
  result = lifestuff_elements->public_id->RemoveContact(my_public_id,
                                                        contact_public_id);
  if (result != kSuccess)
    DLOG(ERROR) << "Failed remove contact in RemoveContact.";

  return result;
}

int LifeStuff::ChangeProfilePicture(
    const std::string &my_public_id,
    const std::string &profile_picture_contents) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in ChangeProfilePicture.";
    return result;
  }

  if (profile_picture_contents.empty() ||
      profile_picture_contents.size() > kFileRecontructionLimit) {
    DLOG(ERROR) << "Contents of picture inadequate("
                << profile_picture_contents.size() << "). Good day!";
    return kGeneralError;
  }

  // Message construction
  InboxItem message(kContactProfilePicture);
  message.sender_public_id = my_public_id;

  if (profile_picture_contents != kBlankProfilePicture) {
    // Write contents
    fs::path profile_picture_path(
        lifestuff_elements->user_storage->mount_dir() /
        fs::path("/").make_preferred() /
        std::string(my_public_id +
                    "_profile_picture" +
                    drive::kMsHidden.string()));
    if (WriteHiddenFile(profile_picture_path,
                        profile_picture_contents,
                        true) != kSuccess) {
      DLOG(ERROR) << "Failed to write profile picture file: "
                  << profile_picture_path;
      return kGeneralError;
    }


    // Get datamap
    std::string data_map;
    std::string reconstructed;
    int count(0), limit(100);
    while (reconstructed != profile_picture_contents && count++ < limit) {
      data_map.clear();
      result = lifestuff_elements->user_storage->GetHiddenFileDataMap(
                  profile_picture_path,
                  &data_map);
      if ((result != kSuccess || data_map.empty()) && count == limit) {
        DLOG(ERROR) << "Failed obtaining DM of profile picture: " << result
                    << ", file: " << profile_picture_path;
        return result;
      }

      reconstructed = lifestuff_elements->user_storage->ConstructFile(data_map);
      Sleep(bptime::milliseconds(50));
    }
    message.content.push_back(data_map);
  } else {
    message.content.push_back(kBlankProfilePicture);
  }

  // Set in session
  lifestuff_elements->session->set_profile_picture_data_map(my_public_id,
                                                            message.content[0]);

  // Send to everybody
  lifestuff_elements->message_handler->SendEveryone(message);

  return kSuccess;
}

std::string LifeStuff::GetOwnProfilePicture(const std::string &my_public_id) {
  // Read contents, put them in a string, give them back. Should not be a file
  // over a certain size (kFileRecontructionLimit).
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in ChangeProfilePicture.";
    return "";
  }

  fs::path profile_picture_path(lifestuff_elements->user_storage->mount_dir() /
                                fs::path("/").make_preferred() /
                                std::string(my_public_id +
                                            "_profile_picture" +
                                            drive::kMsHidden.string()));
  std::string profile_picture_contents;
  if (ReadHiddenFile(profile_picture_path,
                     &profile_picture_contents) != kSuccess ||
      profile_picture_contents.empty()) {
    DLOG(ERROR) << "Failed reading profile picture: " << profile_picture_path;
    return "";
  }

  return profile_picture_contents;
}

std::string LifeStuff::GetContactProfilePicture(
    const std::string &my_public_id,
    const std::string &contact_public_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetContactProfilePicture.";
    return "";
  }

  // Look up data map in session.
  Contact contact;
  result = lifestuff_elements->session->contact_handler_map()
               [my_public_id]->ContactInfo(contact_public_id, &contact);
  if (result != kSuccess || contact.profile_picture_data_map.empty()) {
    DLOG(ERROR) << "No such contact(" << result << "): " << contact_public_id;
    return "";
  }

  // Might be blank
  if (contact.profile_picture_data_map == kBlankProfilePicture) {
    DLOG(INFO) << "Blank image detected. No reconstruction needed.";
    return kBlankProfilePicture;
  }

  // Read contents, put them in a string, give them back. Should not be
  // over a certain size (kFileRecontructionLimit).
  return lifestuff_elements->user_storage->ConstructFile(
            contact.profile_picture_data_map);
}

ContactMap LifeStuff::GetContacts(const std::string &my_public_id,
                                  uint16_t bitwise_status) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetContacts.";
    return ContactMap();
  }

  return lifestuff_elements->session->contact_handler_map()
             [my_public_id]->GetContacts(bitwise_status);
}

std::vector<std::string> LifeStuff::PublicIdsList() const {
  std::vector<std::string> public_ids;
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << lifestuff_elements->state;
    return public_ids;
  }


  // Retrieve all keys
  std::transform(lifestuff_elements->session->contact_handler_map().begin(),
                 lifestuff_elements->session->contact_handler_map().end(),
                 std::back_inserter(public_ids),
                 std::bind(&ContactHandlerMap::value_type::first, args::_1));


  return public_ids;
}

/// Messaging
int LifeStuff::SendChatMessage(const std::string &sender_public_id,
                               const std::string &receiver_public_id,
                               const std::string &message) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << lifestuff_elements->state;
    return kGeneralError;
  }

  if (message.size() > kMaxChatMessageSize) {
    DLOG(ERROR) << "Message too large: " << message.size();
    return kGeneralError;
  }

  InboxItem inbox_item(kChat);
  inbox_item.receiver_public_id = receiver_public_id;
  inbox_item.sender_public_id = sender_public_id;
  inbox_item.content.push_back(message);

  return lifestuff_elements->message_handler->Send(sender_public_id,
                                                   receiver_public_id,
                                                   inbox_item);
}

int LifeStuff::SendFile(const std::string &sender_public_id,
                        const std::string &receiver_public_id,
                        const fs::path &absolute_path) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << lifestuff_elements->state;
    return kGeneralError;
  }

  std::string serialised_datamap;
  int result(lifestuff_elements->user_storage->GetDataMap(absolute_path,
                                                          &serialised_datamap));
  if (result != kSuccess || serialised_datamap.empty()) {
    DLOG(ERROR) << "Failed to get DM for " << absolute_path << ": " << result;
    return result;
  }

  InboxItem inbox_item(kFileTransfer);
  inbox_item.receiver_public_id = receiver_public_id;
  inbox_item.sender_public_id = sender_public_id;
  inbox_item.content.push_back(absolute_path.filename().string());
  inbox_item.content.push_back(serialised_datamap);

  result = lifestuff_elements->message_handler->Send(sender_public_id,
                                                     receiver_public_id,
                                                     inbox_item);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to send message: " << result;
    return result;
  }

  return kSuccess;
}

int LifeStuff::AcceptSentFile(const std::string &identifier,
                              const fs::path &absolute_path,
                              std::string *file_name) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << lifestuff_elements->state;
    return kGeneralError;
  }

  if ((absolute_path.empty() && !file_name) ||
      (!absolute_path.empty() && file_name)) {
    DLOG(ERROR) << "Wrong parameters given. absolute_path and file_name are "
                << "mutually exclusive.";
    return kGeneralError;
  }

  std::string serialised_identifier, saved_file_name, serialised_data_map;
  int result(
      lifestuff_elements->user_storage->ReadHiddenFile(
          mount_path() / fs::path("/").make_preferred() /
              std::string(identifier + drive::kMsHidden.string()),
          &serialised_identifier));
  if (result != kSuccess || serialised_identifier.empty()) {
    DLOG(ERROR) << "No such identifier found: " << result;
    return result == kSuccess ? kGeneralError : result;
  }

  GetFilenameData(serialised_identifier,
                  &saved_file_name,
                  &serialised_data_map);
  if (saved_file_name.empty() || serialised_data_map.empty()) {
    DLOG(ERROR) << "Failed to get filename or datamap.";
    return kGeneralError;
  }

  drive::DataMapPtr data_map_ptr(ParseSerialisedDataMap(serialised_data_map));
  if (!data_map_ptr) {
    DLOG(ERROR) << "Corrupted DM in file";
    return kGeneralError;
  }

  if (absolute_path.empty()) {
    fs::path store_path(mount_path() / kMyStuff / kDownloadStuff);
    std::string adequate_name(GetNameInPath(store_path, saved_file_name));
    if (adequate_name.empty()) {
      DLOG(ERROR) << "No name found to work for saving the file.";
      return kGeneralError;
    }
    result = lifestuff_elements->user_storage->InsertDataMap(
                 store_path / adequate_name,
                 serialised_data_map);
    *file_name = adequate_name;
  } else {
    result = lifestuff_elements->user_storage->InsertDataMap(
                 absolute_path,
                 serialised_data_map);
  }
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed inserting DM: " << result;
    return result;
  }

  return kSuccess;
}

int LifeStuff::RejectSentFile(const std::string &identifier) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << lifestuff_elements->state;
    return kGeneralError;
  }

  fs::path hidden_file(mount_path() /
                       fs::path("/").make_preferred() /
                       std::string(identifier + drive::kMsHidden.string()));
  return lifestuff_elements->user_storage->DeleteHiddenFile(hidden_file);
}

/// Filesystem
int LifeStuff::ReadHiddenFile(const fs::path &absolute_path,
                              std::string *content) const {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << lifestuff_elements->state;
    return kGeneralError;
  }

  return lifestuff_elements->user_storage->ReadHiddenFile(absolute_path,
                                                          content);
}

int LifeStuff::WriteHiddenFile(const fs::path &absolute_path,
                               const std::string &content,
                               bool overwrite_existing) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << lifestuff_elements->state;
    return kGeneralError;
  }

  return lifestuff_elements->user_storage->WriteHiddenFile(absolute_path,
                                                           content,
                                                           overwrite_existing);
}

int LifeStuff::DeleteHiddenFile(const fs::path &absolute_path) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << lifestuff_elements->state;
    return kGeneralError;
  }

  return lifestuff_elements->user_storage->DeleteHiddenFile(absolute_path);
}

/// Private Shares
int LifeStuff::CreatePrivateShareFromExistingDirectory(
    const std::string &my_public_id,
    const fs::path &directory_in_lifestuff_drive,
    const StringIntMap &contacts,
    std::string *share_name,
    StringIntMap *results) {
  BOOST_ASSERT(share_name);
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in "
                << "CreatePrivateShareFromExistingDirectory.";
    return result;
  }

  *share_name =  directory_in_lifestuff_drive.filename().string();
  boost::system::error_code error_code;
  if (fs::exists(directory_in_lifestuff_drive, error_code)) {
    fs::path share_dir(lifestuff_elements->user_storage->mount_dir() /
                       drive::kMsShareRoot /
                       fs::path("/").make_preferred() / (*share_name));
    int index(0);
    while (fs::exists(share_dir, error_code)) {
      share_dir = lifestuff_elements->user_storage->mount_dir() /
                        drive::kMsShareRoot /
                        fs::path("/").make_preferred() /
                        ((*share_name) + "_" + IntToString(index));
      ++index;
    }

    result = CopyDir(directory_in_lifestuff_drive, share_dir);
    if (result != kSuccess)
      return result;
    if (!fs::remove_all(directory_in_lifestuff_drive, error_code))
      return kGeneralError;

    return lifestuff_elements->user_storage->CreateShare(my_public_id,
              share_dir, contacts, drive::kMsPrivateShare, results);
  } else {
    DLOG(ERROR) << "Target Directory doesn't exist";
    return kNoShareTarget;
  }
}

int LifeStuff::CreateEmptyPrivateShare(const std::string &my_public_id,
                                       const StringIntMap &contacts,
                                       std::string *share_name,
                                       StringIntMap *results) {
  BOOST_ASSERT(share_name);
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in CreateEmptyPrivateShare.";
    return result;
  }

  fs::path share_dir(lifestuff_elements->user_storage->mount_dir() /
                     drive::kMsShareRoot /
                     fs::path("/").make_preferred() / (*share_name));
  boost::system::error_code error_code;
  int index(0);
  // TODO(Team): shall use function via drive to test the existence of directory
  while (fs::exists(share_dir, error_code)) {
    share_dir = lifestuff_elements->user_storage->mount_dir() /
                      drive::kMsShareRoot /
                      fs::path("/").make_preferred() /
                      ((*share_name) + "_" + IntToString(index));
    ++index;
  }
  fs::create_directory(share_dir, error_code);
  if (error_code) {
    DLOG(ERROR) << "Failed creating My Stuff: " << error_code.message();
    return kGeneralError;
  }
  *share_name = share_dir.filename().string();

  return lifestuff_elements->user_storage->CreateShare(my_public_id,
            share_dir, contacts, drive::kMsPrivateShare, results);
}

int LifeStuff::GetPrivateShareList(const std::string &my_public_id,
                                   StringIntMap *shares_names) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetPrivateShareList.";
    return result;
  }

  return lifestuff_elements->user_storage->GetAllShares(shares_names);
}

int LifeStuff::GetPrivateShareMemebers(const std::string &my_public_id,
                                       const std::string &share_name,
                                       StringIntMap *shares_members) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetPrivateShareMemebers.";
    return result;
  }
  fs::path share_dir(lifestuff_elements->user_storage->mount_dir() /
                     drive::kMsShareRoot /
                     fs::path("/").make_preferred() / share_name);
  return lifestuff_elements->user_storage->GetAllShareUsers(share_dir,
                                                            shares_members);
}

int LifeStuff::GetPrivateSharesIncludingMember(
    const std::string &my_public_id,
    const std::string &contact_public_id,
    std::vector<std::string> *shares_names) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetPrivateShareList.";
    return result;
  }

  StringIntMap all_shares_names;
  result = lifestuff_elements->user_storage->GetAllShares(&all_shares_names);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed getting all shares in "
                << "GetPrivateSharesIncludingMember.";
    return result;
  }

  for (auto it = all_shares_names.begin(); it != all_shares_names.end(); ++it) {
    StringIntMap share_members;
    fs::path share_dir(lifestuff_elements->user_storage->mount_dir() /
                       drive::kMsShareRoot /
                      fs::path("/").make_preferred() / (*it).first);
    result = lifestuff_elements->user_storage->GetAllShareUsers(share_dir,
                                                  &share_members);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to get members for " << share_dir.string();
    } else {
      std::vector<std::string> member_ids;
      for (auto itr = share_members.begin();
           itr != share_members.end(); ++itr)
        member_ids.push_back((*itr).first);
      auto itr(std::find(member_ids.begin(), member_ids.end(),
                         contact_public_id));
      if (itr != member_ids.end())
        shares_names->push_back((*it).first);
    }
  }
  return kSuccess;
}

int LifeStuff::AcceptPrivateShareInvitation(
    std::string *share_name,
    const std::string &my_public_id,
    const std::string &contact_public_id,
    const std::string &share_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in AcceptPrivateShareInvitation.";
    return result;
  }
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
  fs::path hidden_file(mount_path() / drive::kMsShareRoot /
                       fs::path("/").make_preferred() /
                       std::string(temp_name + drive::kMsHidden.string()));
  std::string serialised_share_data;
  result = lifestuff_elements->user_storage->ReadHiddenFile(hidden_file,
                &serialised_share_data);
  if (result != kSuccess || serialised_share_data.empty()) {
    DLOG(ERROR) << "No such identifier found: " << result;
    return result == kSuccess ? kGeneralError : result;
  }
  Message message;
  message.ParseFromString(serialised_share_data);

  fs::path relative_path(message.content(2));
  std::string directory_id(message.content(3));
  asymm::Keys share_keyring;
  if (message.content_size() > 4) {
      share_keyring.identity = message.content(4);
      share_keyring.validation_token = message.content(5);
      asymm::DecodePrivateKey(message.content(6), &(share_keyring.private_key));
      asymm::DecodePublicKey(message.content(7), &(share_keyring.public_key));
  }

  // remove the temp share invitation file no matter insertion succeed or not
  lifestuff_elements->user_storage->DeleteHiddenFile(hidden_file);

  fs::path share_dir(lifestuff_elements->user_storage->mount_dir() /
                     drive::kMsShareRoot /
                     fs::path("/").make_preferred() / *share_name);
  return lifestuff_elements->user_storage->InsertShare(share_dir,
                                                       share_id,
                                                       contact_public_id,
                                                       share_name,
                                                       directory_id,
                                                       share_keyring);
}

int LifeStuff::RejectPrivateShareInvitation(const std::string &my_public_id,
                                            const std::string &share_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in RejectPrivateShareInvitation.";
    return result;
  }
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
  fs::path hidden_file(mount_path() / drive::kMsShareRoot /
                       fs::path("/").make_preferred() /
                       std::string(temp_name + drive::kMsHidden.string()));
  return lifestuff_elements->user_storage->DeleteHiddenFile(hidden_file);
}

int LifeStuff::EditPrivateShareMembers(const std::string &my_public_id,
                                       const StringIntMap &public_ids,
                                       const std::string &share_name,
                                       StringIntMap *results) {
  StringIntMap share_members;
  int result(GetPrivateShareMemebers(my_public_id, share_name, &share_members));
  if (result != kSuccess)
    return result;

  std::vector<std::string> member_ids;
  for (auto it = share_members.begin(); it != share_members.end(); ++it)
    member_ids.push_back((*it).first);

  StringIntMap members_to_add, members_to_upgrade, members_to_downgrade;
  std::vector<std::string> members_to_remove;
  for (auto it = public_ids.begin(); it != public_ids.end(); ++it) {
    auto itr(std::find(member_ids.begin(), member_ids.end(), (*it).first));
    if (itr != member_ids.end()) {
      // -1 indicates removing the existing member
      // 0 indicates downgrading the existing member
      // 1 indicates upgrading the existing member
      if ((*it).second == kShareRemover)
        members_to_remove.push_back(*itr);
      if (share_members[(*it).first] != (*it).second) {
        if ((*it).second == kShareReadOnly)
            members_to_downgrade.insert(*it);
        if ((*it).second >= kShareReadWrite)
            members_to_upgrade.insert(*it);
      }
    } else {
      // a non-existing user indicates an adding
      members_to_add.insert(*it);
    }
  }
  fs::path share_dir(lifestuff_elements->user_storage->mount_dir() /
                     drive::kMsShareRoot /
                     fs::path("/").make_preferred() / share_name);
  // Add new users
  if (!members_to_add.empty()) {
    StringIntMap add_users_results;
    lifestuff_elements->user_storage->AddShareUsers(my_public_id,
                                                    share_dir,
                                                    members_to_add,
                                                    drive::kMsPrivateShare,
                                                    &add_users_results);
    results->insert(add_users_results.begin(), add_users_results.end());
  }
  // Remove users
  if (!members_to_remove.empty()) {
    result = lifestuff_elements->user_storage->RemoveShareUsers(
           my_public_id, share_dir, members_to_remove, drive::kMsPrivateShare);
    if (result == kSuccess)
      for (auto it = members_to_remove.begin();
           it != members_to_remove.end(); ++it)
        results->insert(std::make_pair(*it, kSuccess));
    else
      for (auto it = members_to_remove.begin();
           it != members_to_remove.end(); ++it)
        results->insert(std::make_pair(*it, result));
  }
  // Upgrade users
  if (!members_to_upgrade.empty()) {
    for (auto it = members_to_upgrade.begin();
              it != members_to_upgrade.end(); ++it) {
      result = lifestuff_elements->user_storage->SetShareUsersRights(
                          my_public_id, share_dir, (*it).first, (*it).second,
                          drive::kMsPrivateShare);
      results->insert(std::make_pair((*it).first, result));
    }
  }
  // Downgrade users
  if (!members_to_downgrade.empty()) {
    result = lifestuff_elements->user_storage->DowngradeShareUsersRights(
                    my_public_id, share_dir,
                    members_to_downgrade, results, drive::kMsPrivateShare);
    if (result != kSuccess)
      return result;
  }
  return kSuccess;
}

int LifeStuff::DeletePrivateShare(const std::string &my_public_id,
                                  const std::string &share_name) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in DeletePrivateShare.";
    return result;
  }

  fs::path share_dir(lifestuff_elements->user_storage->mount_dir() /
                     drive::kMsShareRoot /
                     fs::path("/").make_preferred() / share_name);
  return lifestuff_elements->user_storage->StopShare(my_public_id, share_dir);
}

int LifeStuff::LeavePrivateShare(const std::string &my_public_id,
                                 const std::string &share_name) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in LeavePrivateShare.";
    return result;
  }

  fs::path share_dir(lifestuff_elements->user_storage->mount_dir() /
                     drive::kMsShareRoot /
                     fs::path("/").make_preferred() / share_name);
  return lifestuff_elements->user_storage->RemoveShare(share_dir, my_public_id);
}

///
int LifeStuff::state() const { return lifestuff_elements->state; }

fs::path LifeStuff::mount_path() const {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << lifestuff_elements->state;
    return fs::path();
  }

  return lifestuff_elements->user_storage->mount_dir();
}


}  // namespace lifestuff

}  // namespace maidsafe
