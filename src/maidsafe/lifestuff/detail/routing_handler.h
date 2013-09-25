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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_ROUTING_HANDLER_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_ROUTING_HANDLER_H_

#include <functional>
#include <string>
#include <mutex>
#include <condition_variable>

#include "maidsafe/routing/routing_api.h"

namespace maidsafe {
namespace lifestuff {

typedef routing::GivePublicKeyFunctor GivePublicKeyFunctor;
typedef std::function<void(const NodeId&, const GivePublicKeyFunctor&)> PublicKeyRequestFunction;

class RoutingHandler {
 public:
  typedef routing::Routing Routing;
  typedef routing::Functors Functors;
  typedef routing::ReplyFunctor ReplyFunctor;
  typedef std::pair<std::string, uint16_t> EndPoint;
  typedef boost::asio::ip::udp::endpoint UdpEndPoint;
  typedef std::vector<EndPoint> EndPointVector;
  typedef std::vector<UdpEndPoint> UdpEndPointVector;
  typedef passport::Maid Maid;

  RoutingHandler(const Maid& maid, PublicKeyRequestFunction public_key_request);
  ~RoutingHandler();

  void Join(const EndPointVector& endpoints);

  Routing& routing();
  AsioService& asio_service();

 private:
  RoutingHandler(const RoutingHandler&);
  RoutingHandler& operator=(const RoutingHandler&);

  Functors InitialiseFunctors();

  void OnMessageReceived(const std::string& message, const ReplyFunctor& reply_functor);
  void DoOnMessageReceived(const std::string& message, const ReplyFunctor& reply_functor);
  void OnNetworkStatusChange(const int& network_health);
  void DoOnNetworkStatusChange(const int& network_health);
  void OnPublicKeyRequested(const NodeId& node_id, const GivePublicKeyFunctor& give_key);
  void DoOnPublicKeyRequested(const NodeId& node_id, const GivePublicKeyFunctor& give_key);
  void OnNewBootstrapEndpoint(const UdpEndPoint& endpoint);
  void DoOnNewBootstrapEndpoint(const UdpEndPoint& endpoint);

  UdpEndPointVector UdpEndpoints(const EndPointVector& bootstrap_endpoints);

  Routing routing_;
  PublicKeyRequestFunction public_key_request_;
  int network_health_;
  std::mutex mutex_;
  std::condition_variable condition_variable_;
  AsioService asio_service_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_ROUTING_HANDLER_H_
