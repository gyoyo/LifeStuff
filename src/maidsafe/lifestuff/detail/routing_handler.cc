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

#include "maidsafe/lifestuff/detail/routing_handler.h"

namespace maidsafe {
namespace lifestuff {

RoutingHandler::RoutingHandler(const Maid& maid, PublicKeyRequestFunction public_key_request)
    : routing_(maid),
      public_key_request_(public_key_request),
      network_health_(),
      mutex_(),
      condition_variable_(),
      asio_service_(2) {
  asio_service_.Start();
}

RoutingHandler::~RoutingHandler() { asio_service_.Stop(); }

void RoutingHandler::Join(const EndPointVector& bootstrap_endpoints) {
  routing_.Join(InitialiseFunctors(), UdpEndpoints(bootstrap_endpoints));
  return;
}

RoutingHandler::Routing& RoutingHandler::routing() { return routing_; }

AsioService& RoutingHandler::asio_service() { return asio_service_; }

RoutingHandler::Functors RoutingHandler::InitialiseFunctors() {
  Functors functors;
  functors.network_status = [this](const int &
                                   network_health) { OnNetworkStatusChange(network_health); };
  functors.request_public_key = [this](
      const NodeId & node_id,
      const routing::GivePublicKeyFunctor & give_key) { OnPublicKeyRequested(node_id, give_key); };
  functors.new_bootstrap_endpoint = [this](const UdpEndPoint &
                                           endpoint) { OnNewBootstrapEndpoint(endpoint); };
  return functors;
}

void RoutingHandler::OnMessageReceived(const std::string& message,
                                       const ReplyFunctor& reply_functor) {
  asio_service_.service().post([=] { DoOnMessageReceived(message, reply_functor); });
}

void RoutingHandler::DoOnMessageReceived(const std::string& /*message*/,
                                         const ReplyFunctor& /*reply_functor*/) {}

void RoutingHandler::OnNetworkStatusChange(const int& network_health) {
  asio_service_.service().post([=] { DoOnNetworkStatusChange(network_health); });
}

void RoutingHandler::DoOnNetworkStatusChange(const int& network_health) {
  if (network_health >= 0) {
    if (network_health >= network_health_)
      LOG(kVerbose) << "Init - " << DebugId(routing_.kNodeId()) << " - Network health is "
                    << network_health << "% (was " << network_health_ << "%)";
    else
      LOG(kWarning) << "Init - " << DebugId(routing_.kNodeId()) << " - Network health is "
                    << network_health << "% (was " << network_health_ << "%)";
  } else {
    LOG(kWarning) << "Init - " << DebugId(routing_.kNodeId()) << " - Network is down ("
                  << network_health << ")";
  }
  network_health_ = network_health;
}

void RoutingHandler::OnPublicKeyRequested(const NodeId& node_id,
                                          const GivePublicKeyFunctor& give_key) {
  asio_service_.service().post([=] { DoOnPublicKeyRequested(node_id, give_key); });
}

void RoutingHandler::DoOnPublicKeyRequested(const NodeId& node_id,
                                            const GivePublicKeyFunctor& give_key) {
  public_key_request_(node_id, give_key);
}

void RoutingHandler::OnNewBootstrapEndpoint(const UdpEndPoint& endpoint) {
  asio_service_.service().post([=] { DoOnNewBootstrapEndpoint(endpoint); });
}

void RoutingHandler::DoOnNewBootstrapEndpoint(const UdpEndPoint& /*endpoint*/) {}

RoutingHandler::UdpEndPointVector RoutingHandler::UdpEndpoints(const EndPointVector& endpoints) {
  std::vector<UdpEndPoint> udp_endpoints;
  for (auto& endpoint : endpoints) {
    UdpEndPoint udp_endpoint;
    udp_endpoint.address(boost::asio::ip::address::from_string(endpoint.first));
    udp_endpoint.port(endpoint.second);
    udp_endpoints.push_back(udp_endpoint);
  }
  return udp_endpoints;
}

}  // namespace lifestuff
}  // namespace maidsafe
