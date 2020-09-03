//
// Network topology:
//
//    (Left - senders)
//       t0     t1                 (t0 = 10.1.0.1)
//        |      |                 (t1 = 10.1.1.1)
//       -----------
//       | bridge1 |
//       -----------
//           |
//       -----------
//       | bridge2 |
//       -----------
//        |      |                 (b0 = 20.1.0.1)
//        b0     b1                (b1 = 20.1.1.1)
//    (Right - receivers)
//
// - Flow from t0 to b0 using BulkSendApplication.
// - Tracing of queues and packet receptions to file "*.tr" and "*.pcap" when
//   tracing is turned on.
//

// System includes.
#include <chrono>
#include <sstream>
#include <string>

#include <boost/filesystem.hpp>

// ns-3 includes.
#include "ns3/core-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/point-to-point-dumbbell.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/packet-sink.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/ipv4-nix-vector-helper.h"
#include "ns3/config-store-module.h"
#include "ns3/config.h"
#include "ns3/bridge-module.h"
#include "ns3/ipv4.h"
#include "ns3/node.h"

using namespace ns3;

#define START_TIME         0.0       // Seconds
#define S_PORT             911       // Well-known port for server.
#define PAYLOAD_SIZE       1380      // Bytes; Assume an MTU of 1500. Assume 60
                                     // bytes for the IP header (20 bytes + up
                                     // to 40 bytes for options) and a maximum
                                     // of 60 bytes for the TCP header (20 bytes
                                     // + up to 40 bytes for options).
#define HEADER_AND_OPTIONS 120       // Bytes
#define PCAP_LEN           120       // Bytes
#define EDGE_BW            "10Gbps"  // Bandwidth on the edge of the dumbell
#define EDGE_QUEUE_SIZE    10000     // Queue size on the edge
#define EDGE_DELAY_US      500       // Delay on the edge


// For logging.
NS_LOG_COMPONENT_DEFINE ("main");

const int PRINT_PERIOD = 2;  // sec
std::vector<Ptr<PacketSink>> sinks;

void PrintStats ()
{
  NS_LOG_INFO (Simulator::Now ().GetSeconds () << " s:");
  for (auto& sink : sinks)
    {
      int num_socks = sink->GetSockets ().size ();
      if (num_socks == 0)
        {
          NS_LOG_WARN ("No sockets for this sink!");
        }
      else
        {
          NS_ABORT_UNLESS (num_socks == 1);
          Ptr<TcpSocketBase> sock = DynamicCast<TcpSocketBase> (
            sink->GetSockets ().front ());
          TcpSocketBase::Stats stats = sock->GetStats ();
          NS_LOG_INFO ("  " << (sock->GetReceivingBbr () ? "BBR" : "Other") <<
                       " - avg tput: " << stats.tputMbps <<
                       " Mb/s, avg lat: " << stats.avgLat.GetMicroSeconds () <<
                       " us, pending ACKs: " << sock->GetNumPendingAcks ());
        }
    }
  Simulator::Schedule (Seconds (PRINT_PERIOD), PrintStats);
}


void ParseEdgeDelayString (const std::string &delay_string,
                             std::vector<uint32_t>& edgeDelays,
                             uint32_t num_flows)
{
  if (delay_string.at (0) == '[' &&
      delay_string.at (delay_string.length () - 1) == ']')
    {
      // One delay value for all node pairs
      uint32_t delay = std::stoi (
        delay_string.substr (1, delay_string.length () - 2));
      for (uint32_t i = 0; i < num_flows; ++i)
        {
          edgeDelays.push_back (delay);
        }
  }
  else
    {
      // Parse comma-seperated list
      uint32_t prev_size = edgeDelays.size ();
      std::stringstream ss (delay_string);
      while (ss.good ())
        {
          std::string edge_delay;
          getline (ss, edge_delay, ',');
          if (! edge_delay.empty ())
            {
              edgeDelays.push_back (std::stoi (edge_delay));
            }
        }
      NS_ABORT_UNLESS (edgeDelays.size () - prev_size == num_flows);
    }
}


int main (int argc, char *argv[])
{
  // Parse command line arguments.
  double btlBwMbps = 10;
  double btlDelUs = 5000;
  uint32_t btlQueP = 1000;
  uint32_t unfairFlows = 1;
  uint32_t otherFlows = 0;
  std::string unfairProto = "ns3::TcpBbr";
  std::string otherProto = "ns3::TcpNewReno";
  std::stringstream delaySs;
  delaySs << "[" << EDGE_DELAY_US << "]";
  std::string unfairEdgeDelaysUs = delaySs.str ();
  std::string otherEdgeDelaysUs = unfairEdgeDelaysUs;
  uint32_t payloadB = PAYLOAD_SIZE;
  bool enableUnfair = false;
  std::string fairShareType = "Mathis";
  std::string ackPacingType = "Calc";
  std::string modelFlp = "";
  double durS = 20;
  double warmupS = 5;
  bool pcap = false;
  bool trace = false;
  boost::filesystem::path outDir = ".";
  const char *edge_delay_usage = "List of the edge delays (us) for unfair flows in the "
                                 "dumbbell topology seperated by comma."
                                 "Be mindful that both left and right edge will have the same delay. "
                                 "Edges will have the default delay (500us) if not specified"
                                 "(e.g. \"1000,500,1000,2000\"). Also, there's a shortcut to specify the same "
                                 "delay for all flows, using [1000] instead of comma seperated string.";
  CommandLine cmd;
  cmd.AddValue ("bottleneck_bandwidth_Mbps", "Bandwidth for the bottleneck link (Mbps).", btlBwMbps);
  cmd.AddValue ("bottleneck_delay_us", "Delay across the bottleneck link (us).", btlDelUs);
  cmd.AddValue ("bottleneck_queue_p", "Router queue size at bottleneck link (packets).", btlQueP);
  cmd.AddValue ("unfair_flows", "Number of \"unfair\" flows.", unfairFlows);
  cmd.AddValue ("unfair_proto", "The TCP variant to use (e.g., \"ns3::TcpBbr\") for the \"unfair\" flows.", unfairProto);
  cmd.AddValue ("other_flows", "Number of \"fair\" flows.", otherFlows);
  cmd.AddValue ("other_proto", "The TCP variant to use (e.g., \"ns3::TcpCubic\") for the \"fair\" flows.", otherProto);
  cmd.AddValue ("unfair_edge_delays_us", edge_delay_usage, unfairEdgeDelaysUs);
  cmd.AddValue ("other_edge_delays_us", "Edge delays for other flows (us). See '--unfair_edge_delay_us' for more info.", otherEdgeDelaysUs);
  cmd.AddValue ("payload_B", "Size of a single packet payload (bytes)", payloadB);
  cmd.AddValue ("enable_mitigation", "Enable unfairness mitigation (true or false).", enableUnfair);
  cmd.AddValue ("fair_share_type", "How to estimate the bandwidth fair share.", fairShareType);
  cmd.AddValue ("ack_pacing_type", "How to estimate ACK pacing interval.", ackPacingType);
  cmd.AddValue ("model", "Path to the model file.", modelFlp);
  cmd.AddValue ("duration_s", "Simulation duration (s).", durS);
  cmd.AddValue ("warmup_s", "Time before delaying ACKs (s)", warmupS);
  cmd.AddValue ("pcap", "Record a pcap trace from each port (true or false).", pcap);
  cmd.AddValue ("trace", "Enable tracing (true or false).", trace);
  cmd.AddValue ("out_dir", "Directory in which to store output files.", outDir);
  cmd.Parse (argc, argv);

  // Must specify at least one flow.
  NS_ABORT_UNLESS (unfairFlows + otherFlows > 0);
  // Verify the specified protocols.
  NS_ABORT_UNLESS (unfairProto == "ns3::TcpNewReno" ||
                   unfairProto == "ns3::TcpCubic" ||
                   unfairProto == "ns3::TcpBbr");
  NS_ABORT_UNLESS (otherProto == "ns3::TcpNewReno" ||
                   otherProto == "ns3::TcpCubic" ||
                   otherProto == "ns3::TcpBbr");
  // Make sure that the MTU is large enough.
  uint32_t mtu = payloadB + HEADER_AND_OPTIONS;
  // Number of nodes.
  uint32_t numNodes = unfairFlows + otherFlows;
  // Bottleneck link bandwidth.
  std::stringstream btlBwSs;
  btlBwSs << btlBwMbps << "Mbps";
  std::string btlBw = btlBwSs.str ();
  // Bottleneck link delay.
  std::stringstream btlDelSs;
  btlDelSs << btlDelUs << "us";
  std::string btlDel = btlDelSs.str ();
  // Bottleneck queue capacity.
  std::stringstream btlQueSs;
  btlQueSs << btlQueP << "p";
  std::string btlQue = btlQueSs.str ();
  // Edge delays.
  std::vector<uint32_t> edgeDelays;
  ParseEdgeDelayString (unfairEdgeDelaysUs, edgeDelays, unfairFlows);
  ParseEdgeDelayString (otherEdgeDelaysUs, edgeDelays, otherFlows);

  /////////////////////////////////////////
  // Turn on logging and report parameters.
  // Note: For BBR, other components that may be of interest include "TcpBbr"
  //       and "BbrState".
  LogComponentEnable ("main", LOG_LEVEL_INFO);


  NS_LOG_INFO ("\nBottleneck link bandwidth (Mbps): " << btlBwMbps <<
               "\nBottleneck link delay (us): " << btlDelUs <<
               "\nBottleneck router queue capacity (p): "<< btlQueP <<
               "\nEdge bandwidth: " << EDGE_BW <<
               "\nUnfair flows: " << unfairFlows <<
               "\nUnfair protocol: " << unfairProto <<
               "\nOther flows: " << otherFlows <<
               "\nOther protocol: " << otherProto <<
               "\nUnfair flows edge delays (us): " << unfairEdgeDelaysUs <<
               "\nOther flows edge delays (us): " << otherEdgeDelaysUs <<
               "\nPacket payload size (B): " << payloadB <<
               "\nEnable unfairness mitigation: " <<
               (enableUnfair ? "yes" : "no") <<
               "\nFair share estimation type: " << fairShareType <<
               "\nACK pacing estimation type: " << ackPacingType <<
               "\nModel: " << modelFlp <<
               "\nSimulation duration (s): " << durS <<
               "\nWarmup (s): " << warmupS <<
               "\nCapture PCAP: " << (pcap ? "yes" : "no") <<
               "\nCapture traces: " << (trace ? "yes" : "no") <<
               "\nOutput directory: " << outDir << "\n");

  /////////////////////////////////////////
  // Configure parameters.
  NS_LOG_INFO ("Setting configuration parameters.");
  ConfigStore config;
  config.ConfigureDefaults ();
  // // Select which TCP variant to use.
  // Config::SetDefault ("ns3::TcpL4Protocol::SocketType",
  //                     StringValue (otherProto));
  // Set the segment size (otherwise, ns-3's default is 536).
  Config::SetDefault ("ns3::TcpSocket::SegmentSize",
                      UintegerValue (payloadB));
  // Turn off delayed ACKs (so that every packet results in an ACK).
  // Note: BBR still works without this.
  Config::SetDefault ("ns3::TcpSocket::DelAckCount", UintegerValue (0));
  // Increase the capacity of the send and receive buffers to make sure that the
  // experiment is not application-limited.
  Config::SetDefault ("ns3::TcpSocket::SndBufSize", UintegerValue (1'000'000u));
  Config::SetDefault ("ns3::TcpSocket::RcvBufSize", UintegerValue (1'000'000u));
  // Configure TcpSocketBase with the model filepath.
  Config::SetDefault ("ns3::TcpSocketBase::UnfairMitigationEnable",
                      BooleanValue (true));
  Config::SetDefault ("ns3::TcpSocketBase::FairShareEstimationType",
                      StringValue (fairShareType));
  Config::SetDefault ("ns3::TcpSocketBase::AckPacingType",
                      StringValue (ackPacingType));
  Config::SetDefault ("ns3::TcpSocketBase::AckPeriod",
                      TimeValue (MicroSeconds (0)));
  // Configure TcpSocketBase with the model filepath.
  Config::SetDefault ("ns3::TcpSocketBase::Model", StringValue (modelFlp));
  // Configure TcpSocketBase with how long to wait before beginning
  // unfairness mitigation.
  Config::SetDefault ("ns3::TcpSocketBase::UnfairMitigationDelayStart",
                      TimeValue (Seconds (warmupS)));
  // Configure the number of packet records that TcpSocketBase will maintain.
  Config::SetDefault ("ns3::TcpSocketBase::MaxPacketRecords",
                      UintegerValue (10000));

  // p2pRouter is the link connecting bridge 1 and bridge 2 in the
  // graph above (bottleneck router).
  PointToPointHelper p2pRouter (PCAP_LEN);
  p2pRouter.SetDeviceAttribute ("DataRate", StringValue (btlBw));
  p2pRouter.SetChannelAttribute ("Delay", StringValue (btlDel));
  p2pRouter.SetDeviceAttribute ("Mtu", UintegerValue (mtu));
  p2pRouter.SetQueue ("ns3::DropTailQueue", "MaxSize", QueueSizeValue (btlQue));

  // p2pLeaf are symmetric links that connect senders to bridege 1 and
  // receivers to bridge 2. It is used twice in the creation of
  // PointToPointDumbbellHelper
  PointToPointHelper p2pLeaf (PCAP_LEN);
  p2pLeaf.SetDeviceAttribute ("DataRate", StringValue (EDGE_BW));
  p2pLeaf.SetChannelAttribute (
    "Delay", StringValue (std::to_string (EDGE_DELAY_US) + "us"));
  p2pLeaf.SetDeviceAttribute ("Mtu", UintegerValue (mtu));
  p2pLeaf.SetQueue ("ns3::DropTailQueue", "MaxSize",
                    QueueSizeValue (std::to_string (EDGE_QUEUE_SIZE) + "p"));

  PointToPointDumbbellHelper dumbBellTopology (numNodes, p2pLeaf, numNodes,
                                               p2pLeaf, p2pRouter);

  for (uint32_t i = 0; i < numNodes; ++i)
    {
      Ptr<Node> leftNode = dumbBellTopology.GetLeft (i);
      Ptr<Node> rightNode = dumbBellTopology.GetRight (i);

      Ptr<Channel> leftNodeChannel = leftNode->GetDevice (0)->GetChannel ();
      Ptr<Channel> rightNodeChannel = rightNode->GetDevice (0)->GetChannel ();

      leftNodeChannel->SetAttribute (
        "Delay", TimeValue (MicroSeconds (edgeDelays[i])));
      rightNodeChannel->SetAttribute (
        "Delay", TimeValue (MicroSeconds (edgeDelays[i])));
    }

  // Install stack
  InternetStackHelper stack;
  dumbBellTopology.InstallStack (stack);

  // Assign IP Addresses
  dumbBellTopology.AssignIpv4Addresses (Ipv4AddressHelper ("10.1.0.0", "/24"),  // Left Nodes
                                        Ipv4AddressHelper ("20.1.0.0", "/24"),  // Right Nodes
                                        Ipv4AddressHelper ("30.1.0.0", "/24")); // Router address

  NodeContainer leftNodes, rightNodes;
  for (uint32_t k = 0; k < numNodes; ++k)
    {
      leftNodes.Add (dumbBellTopology.GetLeft (k));
      rightNodes.Add (dumbBellTopology.GetRight (k));
    }

  Ptr<Node> leftRTR = dumbBellTopology.GetLeft ();
  Ptr<Node> rightRTR = dumbBellTopology.GetRight ();
  Ptr <Ipv4> ipL_RTR = leftRTR->GetObject<Ipv4> ();
  Ptr <Ipv4> ipR_RTR = rightRTR->GetObject<Ipv4> ();

  Ipv4StaticRoutingHelper staticRouting;
  for (uint32_t i = 0; i < numNodes; ++i)
    {
      Ptr<Ipv4> ipv4 = leftNodes.Get (i)->GetObject<Ipv4> ();
      Ptr<Ipv4StaticRouting> routeTable = staticRouting.GetStaticRouting (ipv4);
      routeTable->AddNetworkRouteTo (Ipv4Address ("0.0.0.0"),
                                     Ipv4Mask ("0.0.0.0"), 1);
    }

  for (uint32_t i = 0; i < numNodes; ++i)
    {
      Ptr<Ipv4> ipv4 = rightNodes.Get (i)->GetObject<Ipv4> ();
      Ptr<Ipv4StaticRouting> routeTable = staticRouting.GetStaticRouting (ipv4);
      routeTable->AddNetworkRouteTo (Ipv4Address ("0.0.0.0"),
                                     Ipv4Mask ("0.0.0.0"), 1);
    }

  Ptr <Ipv4StaticRouting> leftRTR_routeTable = staticRouting.GetStaticRouting (
    ipL_RTR);
  leftRTR_routeTable->AddNetworkRouteTo (Ipv4Address ("20.0.0.0"),
                                         Ipv4Mask ("/7"), 1);

  for (uint32_t i = 0; i < numNodes; ++i)
    {
      leftRTR_routeTable->AddHostRouteTo (
        leftNodes.Get (i)->GetObject<Ipv4> ()->GetAddress (1, 0).GetLocal (),
        int (i + 2));
    }

  Ptr <Ipv4StaticRouting> rightRTR_routeTable = staticRouting.GetStaticRouting (
    ipR_RTR);
  rightRTR_routeTable->AddNetworkRouteTo (Ipv4Address ("10.0.0.0"),
                                          Ipv4Mask ("/7"), 1);
  for (uint32_t i = 0; i < numNodes; ++i)
    {
      rightRTR_routeTable->AddHostRouteTo (
        rightNodes.Get (i)->GetObject<Ipv4> ()->GetAddress (1, 0).GetLocal (),
        int (i + 2));
    }

  uint32_t port = 100;

  PacketSinkHelper sink ("ns3::TcpSocketFactory",
                         InetSocketAddress (Ipv4Address::GetAny (), port));

  ApplicationContainer rightSinkApp = sink.Install (rightNodes);
  rightSinkApp.Start (Seconds (START_TIME));
  rightSinkApp.Stop (Seconds (START_TIME + durS));

  for (uint32_t i = 0; i < numNodes; ++i)
    {
      sinks.push_back (DynamicCast<PacketSink> (rightSinkApp.Get (i)));
    }

  for (uint32_t i = 0; i < numNodes; ++i)
    {
      Ptr <Node> right = rightNodes.Get (i);
      BulkSendHelper sender (
        "ns3::TcpSocketFactory",
        InetSocketAddress (
          right->GetObject<Ipv4> ()->GetAddress (1, 0).GetLocal (), port));
      sender.SetAttribute ("MaxBytes", UintegerValue (0));
      sender.SetAttribute ("SendSize", UintegerValue (payloadB));

      // Set congestion control type. The first unfairFlows flows will use the
      // unfairProto protocol, while the remaining flows will use the otherProto
      // protocol.
      if (i < unfairFlows)
        {
          sender.SetAttribute ("CongestionType", StringValue (unfairProto));
        }
      else
        {
          sender.SetAttribute ("CongestionType", StringValue (otherProto));
        }

      ApplicationContainer sendApps = sender.Install (leftNodes.Get (i));
      sendApps.Start (Seconds (START_TIME));
      sendApps.Stop (Seconds (START_TIME + durS));
    }

  /////////////////////////////////////////
  // Setup tracing (as appropriate).
  NS_LOG_INFO ("Configuring tracing.");

  std::stringstream detailsSs;
  detailsSs <<
    btlBw << "-" <<
    btlDel << "-" <<
    btlQueP << "p-" <<
    unfairFlows << "unfair-" <<
    otherFlows << "other-" <<
    edgeDelays[0];
  for (uint32_t i = 1; i < unfairFlows + otherFlows; ++i)
    {
      detailsSs << "," << edgeDelays[i];
    }
  detailsSs << "us-" <<
    payloadB << "B-" <<
    durS << "s";
  std::string details = detailsSs.str ();

  // Create output directory and base output filepath.
  outDir /= details;
  NS_ABORT_UNLESS (! boost::filesystem::exists (outDir));
  boost::filesystem::create_directory (outDir);
  boost::filesystem::path outFlp = outDir;
  outFlp /= details;

  if (trace)
    {
      NS_LOG_INFO ("Enabling trace files.");
      AsciiTraceHelper ath;
      std::stringstream traceName;
      traceName << outFlp.string () << ".tr";
      p2pRouter.EnableAsciiAll (ath.CreateFileStream (traceName.str ()));
    }
  if (pcap)
    {
      NS_LOG_INFO ("Enabling pcap files.");
      p2pRouter.EnablePcapAll (outFlp.string (), true);
    }

  Simulator::Schedule (Seconds (PRINT_PERIOD), PrintStats);

  /////////////////////////////////////////
  // Run simulation.
  NS_LOG_INFO ("Running simulation.");
  std::chrono::time_point<std::chrono::steady_clock> startTime =
    std::chrono::steady_clock::now ();

  Simulator::Stop (Seconds (durS));
  NS_LOG_INFO ("Simulation time: [" << START_TIME << "," << durS << "]");
  NS_LOG_INFO ("---------------- Start -----------------------");
  config.ConfigureAttributes ();
  Simulator::Run ();
  NS_LOG_INFO ("---------------- Stop ------------------------");

  std::chrono::time_point<std::chrono::steady_clock> stopTime =
    std::chrono::steady_clock::now ();
  NS_LOG_INFO ("Real simulation time (s): " << (stopTime - startTime).count ());

  /////////////////////////////////////////
  // Calculate fairness.
  NS_LOG_INFO ("Calculating fairness.");

  double sumTputMbps = 0;
  double sumTputMbpsSq = 0;
  NS_LOG_INFO ("Flows:");
  for (auto& sink : sinks)
    {
      double tputMbps = sink->GetTotalRx () * 8 / durS / 1e6;
      sumTputMbps += tputMbps;
      sumTputMbpsSq += pow (tputMbps, 2);
      Ptr<TcpSocketBase> sock = DynamicCast<TcpSocketBase> (
        sink->GetSockets ().front ());
      NS_LOG_INFO ("  " << (sock->GetReceivingBbr () ? "BBR" : "Other") <<
                   " - avg tput: " << tputMbps << " Mb/s");
    }
  NS_LOG_INFO ("Jain's fairness index: " <<
               pow (sumTputMbps, 2) / (sinks.size () * sumTputMbpsSq));

  // Done.
  Simulator::Destroy ();
  return 0;
}
