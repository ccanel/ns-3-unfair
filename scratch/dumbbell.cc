//
// Network topology:
//
//       t0     t1                (t0 = 10.1.1.1)
//        |      |                 (t1 = 10.1.1.2)  Note odd addressing
//       -----------
//       | bridge1 |
//       -----------
//           |
//       -----------
//       | bridge2 |
//       -----------
//        |      |                 (b0 = 10.1.1.3)
//        b0     b1                (b1 = 10.1.1.4)
//
// - Flow from t0 to b0 using BulkSendApplication.
// - Tracing of queues and packet receptions to file "*.tr" and "*.pcap" when
//   tracing is turned on.
//

// System includes.
#include <chrono>
#include <sstream>
#include <string>
#include <unordered_set>

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

#define ENABLE_TRACE      false     // Set to "true" to enable trace.
#define START_TIME        0.0       // Seconds
#define S_PORT            911       // Well-known port for server.
#define PACKET_SIZE       1380      // Bytes; Assumes 60 bytes for the IP
                                    // header (20 bytes + up to 40 bytes for
                                    // options) and a maximum of 60 bytes for
                                    // the TCP header (20 bytes + up to 40
                                    // bytes for options).
#define MTU               1500      // Bytes
#define HEADER_AND_OPTION 120       // Bytes
#define PCAP_LEN          200       // Bytes
#define EDGE_BW           "10Gbps"  // Bandwidth on the edge of the dumbell
#define EDGE_QUEUE_SIZE   10000     // Queue size on the edge
#define EDGE_DELAY_US     500       // Delay on the edge

// For logging.
NS_LOG_COMPONENT_DEFINE ("main");

const int BBR_PRINT_PERIOD = 2;  // sec

std::vector<Ptr<PacketSink>> sinks;
extern bool useReno;

void PrintStats ()
{
  NS_LOG_INFO (Simulator::Now ().GetSeconds () << " s:");
  for (auto& sink : sinks)
    {
      NS_ABORT_UNLESS (sink->GetSockets ().size () == 1);
      Ptr<TcpSocketBase> sock = DynamicCast<TcpSocketBase> (
        sink->GetSockets ().front ());
      TcpSocketBase::Stats stats = sock->GetStats ();
      NS_LOG_INFO ("  " << (sock->GetReceivingBbr () ? "BBR" : "Other") <<
                   " - avg tput: " << stats.tputMbps <<
                   " Mb/s, avg lat: " << stats.avgLat.GetMicroSeconds () <<
                   " us, pending ACKs: " << sock->GetNumPendingAcks ());
    }
  Simulator::Schedule (Seconds (BBR_PRINT_PERIOD), PrintStats);
}


int main (int argc, char *argv[])
{
  // Parse command line arguments.
  double bwMbps = 10;
  double btlDelUs = 5000;
  uint32_t btlQueP = 1000;
  std::string edgeDelayUs = "";
  uint32_t packet_size = PACKET_SIZE;
  uint32_t mtu = MTU;
  double durS = 20;
  double warmupS = 5;
  bool pcap = false;
  bool csv = false;
  std::string modelFlp = "";
  std::string outDir = ".";
  uint32_t unfairFlows = 1;
  uint32_t otherFlows = 0;
  std::string otherProto = "ns3::TcpNewReno";
  bool enableUnfair = false;
  std::string fairShareType = "Mathis";
  std::string ackPacingType = "Calc";

  const char *edge_delay_usage = "List of the edge delays in the dumbbell topology seperated by comma."
                                 "Be mindful that both left and right edge will have the same delay. " 
                                 "Edges will have the default delay if not specified. " 
                                 "(e.g. \"1000,500,1000,2000\")";

  CommandLine cmd;
  cmd.AddValue ("bandwidth_Mbps", "Bandwidth for the bottleneck router (Mbps).", bwMbps);
  cmd.AddValue ("delay_us", "Bottleneck link delay (us).", btlDelUs);
  cmd.AddValue ("queue_capacity_p", "Router queue size at bottleneck router (packets).", btlQueP);
  cmd.AddValue ("edge_delay_us", edge_delay_usage, edgeDelayUs);
  cmd.AddValue ("packet_size", "Size of a single packet (bytes)", packet_size);
  cmd.AddValue ("experiment_duration_s", "Simulation duration (s).", durS);
  cmd.AddValue ("warmup_s", "Time before delaying ACKs (s)", warmupS);
  cmd.AddValue ("pcap", "Record a pcap trace from each port (true or false).", pcap);
  cmd.AddValue ("csv", "Record a csv file for BBR receiver (true or false).", csv);
  cmd.AddValue ("model", "Path to the model file.", modelFlp);
  cmd.AddValue ("out_dir", "Directory in which to store output files.", outDir);
  cmd.AddValue ("unfair_flows", "Number of BBR flows.", unfairFlows);
  cmd.AddValue ("other_flows", "Number of non-BBR flows.", otherFlows);
  cmd.AddValue ("other_proto", "The TCP variant to use (e.g., \"ns3::TcpCubic\") for the non-BBR flows.", otherProto);
  cmd.AddValue ("enable", "Enable unfairness mitigation (true or false).", enableUnfair);
  cmd.AddValue ("fair_share_type", "How to estimate the bandwidth fair share.", fairShareType);
  cmd.AddValue ("ack_pacing_type", "How to estimate ACK pacing interval.", ackPacingType);
  cmd.Parse (argc, argv);

  // Verify the protofol specified for the non-BBR flows.
  NS_ABORT_UNLESS (otherProto == "ns3::TcpNewReno" ||
                   otherProto == "ns3::TcpCubic" ||
                   otherProto == "ns3::TcpBbr");

  uint32_t rttUs = (btlDelUs + EDGE_DELAY_US * 2) * 2;

  // Number of Nodes
  uint32_t num_nodes = unfairFlows + otherFlows;

  // Bandwidth
  std::stringstream bwSs;
  bwSs << bwMbps << "Mbps";
  std::string bw = bwSs.str ();

  // Delay
  std::stringstream btlDelSs;
  btlDelSs << btlDelUs << "us";
  std::string btlDel = btlDelSs.str ();

  // Queue size
  std::stringstream btlQueSs;
  btlQueSs << btlQueP << "p";
  std::string btlQue = btlQueSs.str ();

  double routerToDstBW = bwMbps;
  std::stringstream sndSS;
  sndSS << routerToDstBW << "Mbps";
  std::string btlBWStr = sndSS.str ();

  mtu = packet_size + HEADER_AND_OPTION;

  // Edge delays
  std::vector<uint32_t> edge_delays;
  std::stringstream ss(edgeDelayUs);

  while (ss.good()) {
    std::string edge_delay;
    getline(ss, edge_delay, ',');
    if (!edge_delay.empty()) {
      edge_delays.push_back(std::stoi(edge_delay));
    }
  }



  /////////////////////////////////////////
  // Turn on logging and report parameters.
  // Note: For BBR', other components that may be of interest include "TcpBbr"
  //       and "BbrState".
  LogComponentEnable ("main", LOG_LEVEL_INFO);

  NS_LOG_INFO ("\n" <<
               "Bottleneck router bandwidth: " << bw << "\n" <<
               "Bottleneck router delay: " << btlDel << "\n" <<
               "Edge bandwidth: " << EDGE_BW);

  std::string edge_delay_info = "Edge delays: ";
  for (uint32_t i = 0; i < num_nodes; i++) {
    uint32_t edge_delay_num;
    if (i < edge_delays.size()) {
      edge_delay_num = edge_delays[i];
    } else {
      edge_delay_num = EDGE_DELAY_US;
    }
    edge_delay_info += std::to_string(edge_delay_num) + "us ";
  }

  NS_LOG_INFO(edge_delay_info);

  NS_LOG_INFO( "RTT: " << rttUs << "us\n" <<
               "Packet size: " << packet_size << " bytes\n" <<
               "Bottleneck router queue capacity: "<< btlQueP << " packets\n" <<
               "BBR flows: " << unfairFlows << "\n" <<
               "Non-BBR flows: " << otherFlows << "\n" <<
               "Non-BBR protocol: " << otherProto << "\n" <<
               "Duration: " << durS << "s\n" <<
               "Enable unfairness mitigation: " << (enableUnfair ? "yes" : "no") << "\n" <<
               "Fair share estimation type: " << fairShareType << "\n" <<
               "ACK pacing estimation type: " << ackPacingType << "\n" <<
               "Model: " << modelFlp << "\n");

  /////////////////////////////////////////
  // Configure parameters.
  NS_LOG_INFO ("Setting configuration parameters.");
  ConfigStore config;
  config.ConfigureDefaults ();
  // Select which TCP variant to use.
  Config::SetDefault ("ns3::TcpL4Protocol::SocketType", StringValue (otherProto));
  // Configure the number of TcpBbr flows.
  Config::SetDefault ("ns3::TcpL4Protocol::NumUnfair",
                      UintegerValue (unfairFlows));
  // Set the segment size (otherwise, ns-3's default is 536).
  Config::SetDefault ("ns3::TcpSocket::SegmentSize",
                      UintegerValue (packet_size));
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
  // updateAckPeriod (MicroSeconds(0));
  Config::SetDefault ("ns3::TcpSocketBase::AckPeriod",
                      TimeValue (MicroSeconds (0)));
  // Configure TcpSocketBase with the model filepath.
  Config::SetDefault ("ns3::TcpSocketBase::Model", StringValue (modelFlp));
  // Configure TcpSocketBase with the model filepath.
  Config::SetDefault ("ns3::TcpSocketBase::UnfairMitigationDelayStart",
                      TimeValue (Seconds (warmupS)));
  // Configure the number of packet records that TcpSocketBase will maintain.
  Config::SetDefault ("ns3::TcpSocketBase::MaxPacketRecords",
                      UintegerValue (10000));

  PointToPointHelper p2pRouter (PCAP_LEN);
  p2pRouter.SetDeviceAttribute ("DataRate", StringValue (btlBWStr));
  p2pRouter.SetChannelAttribute ("Delay", StringValue (btlDel));
  p2pRouter.SetDeviceAttribute ("Mtu", UintegerValue (mtu));
  p2pRouter.SetQueue ("ns3::DropTailQueue", "MaxSize", QueueSizeValue (btlQue));

  PointToPointHelper p2pLeaf (PCAP_LEN);
  p2pLeaf.SetDeviceAttribute ("DataRate", StringValue (EDGE_BW));
  p2pLeaf.SetChannelAttribute ("Delay", StringValue (std::to_string(EDGE_DELAY_US) + "us"));
  p2pLeaf.SetDeviceAttribute ("Mtu", UintegerValue (mtu));
  p2pLeaf.SetQueue ("ns3::DropTailQueue", "MaxSize", QueueSizeValue (std::to_string(EDGE_QUEUE_SIZE) + "p"));

  PointToPointDumbbellHelper dumbBellTopology(num_nodes, p2pLeaf, num_nodes, 
                                             p2pLeaf, p2pRouter);

  for (uint32_t i = 0; i < std::min(num_nodes, static_cast<uint32_t>(edge_delays.size())); ++i) {
    Ptr <Node> leftNode = dumbBellTopology.GetLeft(i);
    Ptr <Node> rightNode = dumbBellTopology.GetRight(i);

    Ptr <Channel> leftNodeChannel = leftNode->GetDevice(0)->GetChannel();
    Ptr <Channel> rightNodeChannel = rightNode->GetDevice(0)->GetChannel();

    leftNodeChannel->SetAttribute("Delay", TimeValue(MicroSeconds(edge_delays[i])));
    rightNodeChannel->SetAttribute("Delay", TimeValue(MicroSeconds(edge_delays[i])));
  }

  // Install stack
  InternetStackHelper stack;
  dumbBellTopology.InstallStack(stack);

  // Assign IP Addresses
  dumbBellTopology.AssignIpv4Addresses(Ipv4AddressHelper("10.1.0.0", "/24"),
                                      Ipv4AddressHelper("20.1.0.0", "/24"),
                                      Ipv4AddressHelper("30.1.0.0", "/24"));

  NodeContainer leftNodes, rightNodes;
  for (uint32_t k = 0; k < num_nodes; ++k) {
    leftNodes.Add(dumbBellTopology.GetLeft(k));
    rightNodes.Add(dumbBellTopology.GetRight(k));
  }

  Ptr<Node> leftRTR = dumbBellTopology.GetLeft();
  Ptr<Node> rightRTR = dumbBellTopology.GetRight();
  Ptr <Ipv4> ipL_RTR = leftRTR->GetObject<Ipv4>();
  Ptr <Ipv4> ipR_RTR = rightRTR->GetObject<Ipv4>();

  Ipv4StaticRoutingHelper staticRouting;
  for (uint32_t i = 0; i < num_nodes; ++i) {
    Ptr<Ipv4> ipv4 = leftNodes.Get(i)->GetObject<Ipv4>();
    Ptr<Ipv4StaticRouting> routeTable = staticRouting.GetStaticRouting(ipv4);
    routeTable->AddNetworkRouteTo(Ipv4Address("0.0.0.0"), Ipv4Mask("0.0.0.0"), 1);
    }

  for (uint32_t i = 0; i < num_nodes; ++i) {
    Ptr<Ipv4> ipv4 = rightNodes.Get(i)->GetObject<Ipv4>();
    Ptr<Ipv4StaticRouting> routeTable = staticRouting.GetStaticRouting(ipv4);
    routeTable->AddNetworkRouteTo(Ipv4Address("0.0.0.0"), Ipv4Mask("0.0.0.0"), 1);
  }

  Ptr <Ipv4StaticRouting> leftRTR_routeTable = staticRouting.GetStaticRouting(ipL_RTR);
  leftRTR_routeTable->AddNetworkRouteTo(Ipv4Address("20.0.0.0"), Ipv4Mask("/7"), 1);
    
  for (uint32_t i = 0; i < num_nodes; ++i) {
    leftRTR_routeTable->AddHostRouteTo(
      leftNodes.Get(i)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal(),
      int(i + 2));
  }

  Ptr <Ipv4StaticRouting> rightRTR_routeTable = staticRouting.GetStaticRouting(ipR_RTR);
  rightRTR_routeTable->AddNetworkRouteTo(Ipv4Address("10.0.0.0"), Ipv4Mask("/7"), 1);
  for (uint32_t i = 0; i < num_nodes; ++i) {
    rightRTR_routeTable->AddHostRouteTo(
      rightNodes.Get(i)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal(),
      int(i + 2));
  }

  uint32_t port = 100;

  PacketSinkHelper sink("ns3::TcpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), port));

  ApplicationContainer bottomSinkApp = sink.Install(rightNodes);
  bottomSinkApp.Start(Seconds(START_TIME));
  bottomSinkApp.Stop(Seconds(START_TIME + durS));

  for (uint32_t i = 0; i < num_nodes; ++i) {
    sinks.push_back(DynamicCast<PacketSink>(bottomSinkApp.Get(i)));
  }

  for (uint32_t i = 0; i < num_nodes; ++i) {
    Ptr <Node> right = rightNodes.Get(i);
    BulkSendHelper sender("ns3::TcpSocketFactory",
                              InetSocketAddress(right->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal(),
                                                port));
    sender.SetAttribute("MaxBytes", UintegerValue(0));
    sender.SetAttribute("SendSize", UintegerValue (packet_size));

    // Set congestion control type

    if (i < unfairFlows) {
      sender.SetAttribute("CongestionType", StringValue("ns3::TcpBbr"));
    } else {
      sender.SetAttribute("CongestionType", StringValue(otherProto));
    }
    ApplicationContainer sendApps = sender.Install(leftNodes.Get(i));
    sendApps.Start(Seconds(START_TIME));
    sendApps.Stop(Seconds(START_TIME + durS));
  }

  /////////////////////////////////////////
  // Setup tracing (as appropriate).
  NS_LOG_INFO ("Configuring tracing.");
  std::stringstream detailsSs;
  detailsSs <<
    bw << "-" <<
    rttUs << "us-" <<
    btlQueP << "p-" <<
    unfairFlows << "unfair-" <<
    otherFlows << "other-" <<
    packet_size << "B-" <<
    durS << "s";
  std::string details = detailsSs.str ();

  if (csv) {
    Config::SetDefault ("ns3::TcpSocketBase::CsvFileName",
                      StringValue (outDir + "/" + details + ".csv"));
  }


  if (ENABLE_TRACE) {
    NS_LOG_INFO ("Enabling trace files.");
    AsciiTraceHelper ath;
    std::stringstream traceName;
    traceName << outDir << "/trace-" << details << ".tr";
    p2pRouter.EnableAsciiAll (ath.CreateFileStream (traceName.str ()));
  }
  if (pcap) {
    NS_LOG_INFO ("Enabling pcap files.");
    std::stringstream pcapName;
    pcapName << outDir << "/" << details;
    p2pRouter.EnablePcapAll (pcapName.str (), true);
  }

  Simulator::Schedule (Seconds (BBR_PRINT_PERIOD), PrintStats);

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
               pow(sumTputMbps, 2) / (sinks.size () * sumTputMbpsSq));

  // Done.
  Simulator::Destroy ();
  return 0;
}
