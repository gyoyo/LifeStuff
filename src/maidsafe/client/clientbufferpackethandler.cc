/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#include "maidsafe/client/clientbufferpackethandler.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace maidsafe {

void ExecuteFailureCallback(base::callback_func_type cb,
    boost::recursive_mutex *mutex) {
  base::pd_scoped_lock gaurd(*mutex);
  maidsafe::GenericResponse result;
  result.set_result(kNack);
  std::string ser_result;
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

ClientBufferPacketHandler::ClientBufferPacketHandler(
    maidsafe::StoreManagerInterface *sm, boost::recursive_mutex *mutex)
        : crypto_obj_(),
          ss_(maidsafe::SessionSingleton::getInstance()),
          sm_(sm),
          mutex_(mutex) {
  crypto_obj_.set_hash_algorithm(crypto::SHA_512);
  crypto_obj_.set_symm_algorithm(crypto::AES_256);
}

int ClientBufferPacketHandler::CreateBufferPacket(
    const std::string &owner_id,
    const std::string &public_key,
    const std::string &private_key) {
  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner_id);
  buffer_packet_info.set_ownerpublickey(public_key);
  buffer_packet_info.set_online(1);
//  #ifdef DEBUG
//    printf("buffer_packet_info.online: %i\n", buffer_packet_info.online());
//  #endif
  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj_.AsymSign(
    ser_info, "", private_key, crypto::STRING_STRING));
  std::string bufferpacketname =
    crypto_obj_.Hash(owner_id + "BUFFER", "", crypto::STRING_STRING, true);

  std::string ser_packet;
  buffer_packet.SerializeToString(&ser_packet);
  return sm_->StorePacket(bufferpacketname, ser_packet, BUFFER,
                          maidsafe::PRIVATE, "");
}

int ClientBufferPacketHandler::ChangeStatus(int status,
    const PacketType &type) {
//  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  BufferPacketInfo packet_info;
  GenericPacket user_info;

  std::set<std::string> current_users;
  UserList(&current_users, MPID);

  packet_info.set_owner(ss_->PublicUsername());
  packet_info.set_ownerpublickey(ss_->PublicKey(type));
  packet_info.set_online(status);

  for (std::set<std::string>::iterator p = current_users.begin();
      p != current_users.end(); p++) {
    packet_info.add_users(*p);
  }

  std::string ser_info;
  packet_info.SerializeToString(&ser_info);
  user_info.set_data(ser_info);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) + "BUFFER", "",
      crypto::STRING_STRING, true);
  user_info.set_signature(crypto_obj_.AsymSign(ser_info, "",
      ss_->PrivateKey(type), crypto::STRING_STRING));
  std::string ser_gp;
  user_info.SerializeToString(&ser_gp);

  return sm_->StorePacket(bufferpacketname, ser_gp, BUFFER_INFO,
                          maidsafe::PRIVATE, "");
}

bool ClientBufferPacketHandler::UserList(
    std::set<std::string> *list, PacketType type) {
  switch (type) {
    case MPID: *list = ss_->AuthorisedUsers(); break;
    case MAID: *list = ss_->MaidAuthorisedUsers(); break;
    default: break;
  }
  return true;
}

bool ClientBufferPacketHandler::SetUserList(
    std::set<std::string> list,
    PacketType type) {
  switch (type) {
    case MPID: ss_->SetAuthorisedUsers(list); break;
    case MAID: ss_->SetMaidAuthorisedUsers(list); break;
    default: break;
  }
  return true;
}

int ClientBufferPacketHandler::AddUsers(
    const std::set<std::string> &users,
    const PacketType &type) {
//  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  if (users.empty())
    return -1;

  BufferPacketInfo packet_info;
  GenericPacket user_info;

  std::set<std::string> current_users;
  UserList(&current_users, type);

  std::set<std::string> local_users = users;
  for (std::set<std::string>::iterator p = local_users.begin();
    p != local_users.end(); ++p) {
    current_users.insert(*p);
  }

  packet_info.set_owner(ss_->PublicUsername());
  packet_info.set_ownerpublickey(ss_->PublicKey(type));
  packet_info.set_online(0);

  for (std::set<std::string>::iterator p = current_users.begin();
    p != current_users.end(); p++) {
    packet_info.add_users(*p);
  }

  std::string ser_info;
  packet_info.SerializeToString(&ser_info);
  user_info.set_data(ser_info);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) + "BUFFER", "",
      crypto::STRING_STRING, true);
  user_info.set_signature(crypto_obj_.AsymSign(ser_info, "",
      ss_->PrivateKey(type), crypto::STRING_STRING));

  std::string ser_gp;
  user_info.SerializeToString(&ser_gp);

  int n = sm_->StorePacket(bufferpacketname, ser_gp, BUFFER_INFO,
                           maidsafe::PRIVATE, "");
  if (n == 0)
    SetUserList(users, type);
  return n;
}

int ClientBufferPacketHandler::DeleteUsers(
    const std::set<std::string> &users,
    const PacketType &type) {
//  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  std::set<std::string> current_users;
  if (type == MPID)
    current_users = ss_->AuthorisedUsers();
  else
    current_users = ss_->MaidAuthorisedUsers();

  std::set<std::string> local_users = users;
  for (std::set<std::string>::iterator p = local_users.begin();
      p != local_users.end(); ++p)
    current_users.erase(*p);

  BufferPacketInfo packet_info;
  GenericPacket gp;
  for (std::set<std::string>::iterator p = current_users.begin();
    p != current_users.end(); ++p)
    packet_info.add_users(*p);
  packet_info.set_owner(ss_->PublicUsername());
  packet_info.set_ownerpublickey(ss_->PublicKey(type));
  packet_info.set_online(0);

  std::string ser_info;
  packet_info.SerializeToString(&ser_info);
  gp.set_data(ser_info);
  gp.set_signature(crypto_obj_.AsymSign(ser_info, "", ss_->PrivateKey(type),
      crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) + "BUFFER",
      "", crypto::STRING_STRING, true);
  int n = sm_->StorePacket(bufferpacketname, ser_gp, BUFFER_INFO,
                           maidsafe::PRIVATE, "");
  if (n == 0) {
    if (type == MPID)
      ss_->SetAuthorisedUsers(current_users);
    else
      ss_->SetMaidAuthorisedUsers(current_users);
  }
  return n;
}

int ClientBufferPacketHandler::GetMessages(
    const PacketType &type,
    std::list<ValidatedBufferPacketMessage> *valid_messages) {
  valid_messages->clear();
//  maidsafe::PacketType pt = PacketHandler_PacketType(type);
// TODO(Fraser#5#): 2009-09-15 - Confirm that mutex is not required here
//  base::pd_scoped_lock gaurd(*mutex_);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) + "BUFFER", "",
      crypto::STRING_STRING, true);
  std::string signed_public_key = crypto_obj_.AsymSign(
      ss_->PublicKey(type), "", ss_->PrivateKey(type), crypto::STRING_STRING);
  std::list<std::string> messages;
  if (sm_->LoadMessages(bufferpacketname, ss_->PublicKey(type),
      signed_public_key, &messages) != 0)
    return -1;
  while (!messages.empty()) {
    ValidatedBufferPacketMessage valid_message;
    if (valid_message.ParseFromString(messages.front())) {
      std::string aes_key = crypto_obj_.AsymDecrypt(valid_message.index(), "",
          ss_->PrivateKey(type), crypto::STRING_STRING);
      valid_message.set_message(crypto_obj_.SymmDecrypt(valid_message.message(),
          "", crypto::STRING_STRING, aes_key));
      valid_messages->push_back(valid_message);
      messages.pop_front();
// TODO(Fraser#5#): 2009-09-15 - Add message saying corrupted messge not parsed?
//    } else {
//      valid_message.set_sender("");
//      valid_message.set_message("You got a corrupted message.");
//      valid_message.set_index("");
//      valid_message.set_type(0);
//      valid_messages->push_back(valid_message);
//      messages.pop_front();
    }
  }
  return 0;
}

void ClientBufferPacketHandler::GetBufferPacket(
    const PacketType &type,
    base::callback_func_type cb) {
  std::string bufferpacketname = crypto_obj_.Hash(
      ss_->Id(type) + "BUFFER", "",
      crypto::STRING_STRING, true);
  std::string packet_content;
  sm_->LoadPacket(bufferpacketname, &packet_content);
  maidsafe::GetResponse local_result;
  std::string str_local_result;
  if ((!local_result.ParseFromString(packet_content))||
      (!local_result.has_content())) {
    local_result.set_result(kNack);
    local_result.SerializeToString(&str_local_result);
    cb(str_local_result);
    return;
  }
  maidsafe::GetMessagesResponse msgs_result;
  msgs_result.set_result(kAck);
  BufferPacket bp;
  BufferPacketInfo bpi;
  bp.ParseFromString(local_result.content());
  bpi.ParseFromString(bp.owner_info(0).data());
  std::set<std::string> users;
  for (int i = 0; i < bpi.users_size(); ++i) {
    printf("ClientBufferGetBufferPacket_Callback - AU: %s\n",
            bpi.users(i).c_str());
    users.insert(bpi.users(i));
  }
  ss_->SetAuthorisedUsers(users);


  GenericPacket gp;
  BufferPacketMessage bpm;
  std::string aes_key;
  for (int i = 0; i < bp.messages_size(); ++i) {
    gp = bp.messages(i);
    if (bpm.ParseFromString(gp.data()))
      if ((bpm.type() == ADD_CONTACT_RQST) ||
          (crypto_obj_.AsymCheckSig(gp.data(), gp.signature(),
          bpm.sender_public_key(), crypto::STRING_STRING))) {
        ValidatedBufferPacketMessage msg;
        msg.set_index(bpm.rsaenc_key());
        aes_key = crypto_obj_.AsymDecrypt(msg.index(), "",
            ss_->PrivateKey(type),
            crypto::STRING_STRING);
        msg.set_message(crypto_obj_.SymmDecrypt(bpm.aesenc_message(), "",
            crypto::STRING_STRING, aes_key));
        msg.set_sender(bpm.sender_id());
        msg.set_type(bpm.type());
        std::string ser_msg;
        msg.SerializeToString(&ser_msg);
        msgs_result.add_messages(ser_msg);
      }
  }
  msgs_result.SerializeToString(&str_local_result);
  cb(str_local_result);
}

void ClientBufferPacketHandler::GetBufferPacketInfo(
    const PacketType &type, base::callback_func_type cb) {
  std::string bufferpacketname = crypto_obj_.Hash(
      ss_->Id(type) + "BUFFER", "",
      crypto::STRING_STRING, true);
  std::string packet_content;
  sm_->LoadPacket(bufferpacketname, &packet_content);
  maidsafe::GetResponse local_result;
  std::string str_local_result;
  if ((!local_result.ParseFromString(packet_content))||
      (!local_result.has_content())) {
    local_result.set_result(kNack);
    local_result.SerializeToString(&str_local_result);
    cb(str_local_result);
    return;
  }
  maidsafe::GetMessagesResponse msgs_result;
  msgs_result.set_result(kAck);
  BufferPacket bp;
  BufferPacketInfo bpi;
  bp.ParseFromString(local_result.content());
  bpi.ParseFromString(bp.owner_info(0).data());
  std::set<std::string> users;
  for (int i = 0; i < bpi.users_size(); ++i)
    users.insert(bpi.users(i));
  ss_->SetAuthorisedUsers(users);
  local_result.set_result(kAck);
  local_result.SerializeToString(&str_local_result);
  cb(str_local_result);
}

void ClientBufferPacketHandler::ClearMessages(
    const PacketType &type,
    base::callback_func_type cb) {
//  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) + "BUFFER", "",
      crypto::STRING_STRING, true);
  std::string signed_public_key = crypto_obj_.AsymSign(
      ss_->PublicKey(type), "", ss_->PrivateKey(type), crypto::STRING_STRING);
  std::string non_hex_bufferpacketname("");
  base::decode_from_hex(bufferpacketname, &non_hex_bufferpacketname);
  std::string signed_request = crypto_obj_.AsymSign(
    crypto_obj_.Hash(ss_->PublicKey(type) + signed_public_key +
    non_hex_bufferpacketname, "", crypto::STRING_STRING, false), "",
    ss_->PrivateKey(type), crypto::STRING_STRING);

  sm_->DeletePacket(bufferpacketname, signed_request,
      ss_->PublicKey(type), signed_public_key,
      maidsafe::BUFFER_PACKET_MESSAGE, cb);
}

//  maidsafe::PacketType
//      ClientBufferPacketHandler::PacketHandler_PacketType(
//      const PacketType &type) {
//    //  MPID, MAID, PMID
//    switch (type) {
//      case MAID: return maidsafe::MAID;
//      case PMID: return maidsafe::PMID;
//      default: return maidsafe::MPID;
//    }
//  }

}  // namespace maidsafe
