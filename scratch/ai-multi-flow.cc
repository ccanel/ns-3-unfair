//
// Network topology:
//
//       n0 ------------ (n1/router) -------------- n2
//            10.1.1.x                192.168.1.x
//       10.1.1.1    10.1.1.2   192.16.1.1     192.168.1.2
//
// - Flow from n0 to n2 using BulkSendApplication.
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
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/packet-sink.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/config-store-module.h"
#include "ns3/config.h"

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
#define SRC_TO_ROUTER_BW  "10Gbps"  // Bandwidth from the source to the router.
                                    // This should be configured to be great
                                    // enough such that it is not the
                                    // bottleneck.

// For logging.
NS_LOG_COMPONENT_DEFINE ("main");

const int BBR_PRINT_PERIOD = 2;  // sec

std::vector<Ptr<PacketSink>> sinks;
extern bool useReno;


Ptr<PacketSink> CreateFlow(uint16_t port, Ipv4InterfaceContainer i1i2,
                           NodeContainer nodes, double durS, uint32_t packet_size,
                           const std::string& congestion_type)
{
  // Source (at node 0).
  BulkSendHelper src ("ns3::TcpSocketFactory",
                      InetSocketAddress (i1i2.GetAddress (1), port));
  // Set the amount of data to send in bytes (0 for unlimited).
  src.SetAttribute ("MaxBytes", UintegerValue (0));
  src.SetAttribute ("SendSize", UintegerValue (packet_size));
  src.SetAttribute ("CongestionType", StringValue (congestion_type));
  ApplicationContainer srcApp = src.Install (nodes.Get (0));
  srcApp.Start (Seconds (START_TIME));
  srcApp.Stop (Seconds (START_TIME + durS));

  // Destination (at node 2).
  PacketSinkHelper dst ("ns3::TcpSocketFactory",
                         InetSocketAddress (Ipv4Address::GetAny (), port));
  ApplicationContainer dstApp = dst.Install (nodes.Get (2));
  dstApp.Start (Seconds (START_TIME));
  dstApp.Stop (Seconds (START_TIME + durS));
  return DynamicCast<PacketSink> (dstApp.Get (0));
}


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
  double delUs = 5000;
  uint32_t queP = 1000;
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

  CommandLine cmd;
  cmd.AddValue ("bandwidth_Mbps", "Bandwidth for both links (Mbps).", bwMbps);
  cmd.AddValue ("delay_us", "Link delay (us). RTT is 4x this value.", delUs);
  cmd.AddValue ("queue_capacity_p", "Router queue size (packets).", queP);
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

  uint32_t rttUs = delUs * 4;
  std::stringstream bwSs;
  bwSs << bwMbps << "Mbps";
  std::string bw = bwSs.str ();
  std::stringstream delSs;
  delSs << delUs << "us";
  std::string del = delSs.str ();
  std::stringstream queSs;
  queSs << queP << "p";
  std::string que = queSs.str ();

  double routerToDstBW = bwMbps;
  std::stringstream sndSS;
  sndSS << routerToDstBW << "Mbps";
  std::string routerToDstBWStr = sndSS.str ();

  mtu = packet_size + HEADER_AND_OPTION;

  /////////////////////////////////////////
  // Turn on logging and report parameters.
  // Note: For BBR', other components that may be of interest include "TcpBbr"
  //       and "BbrState".
  LogComponentEnable ("main", LOG_LEVEL_INFO);

  NS_LOG_INFO ("\n" <<
               "Src to router bandwidth: " << SRC_TO_ROUTER_BW << "\n" <<
               "Src to router delay: " << del << "\n" <<
               "Router to dst bandwidth: " << bw << "\n" <<
               "Router to dst delay: " << del << "\n" <<
               "RTT: " << rttUs << "us\n" <<
               "Packet size: " << packet_size << " bytes\n" <<
               "Router queue capacity: "<< queP << " packets\n" <<
               "BBR flows: " << unfairFlows << "\n" <<
               "Non-BBR flows: " << otherFlows << "\n" <<
               "Non-BBR protocol: " << otherProto << "\n" <<
               "Warmup: " << warmupS << "s\n" <<
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

  /////////////////////////////////////////
  // Create nodes.
  NS_LOG_INFO ("Creating nodes.");
  NodeContainer nodes;  // 0: source, 1: router, 2: sink
  nodes.Create (3);

  /////////////////////////////////////////
  // Create channels.
  NS_LOG_INFO ("Creating channels.");
  NodeContainer n0Ton1 = NodeContainer (nodes.Get (0), nodes.Get (1));
  NodeContainer n1Ton2 = NodeContainer (nodes.Get (1), nodes.Get (2));

  /////////////////////////////////////////
  // Create links.
  NS_LOG_INFO ("Creating links.");

  // Server to Router.
  PointToPointHelper p2p (PCAP_LEN);
  p2p.SetDeviceAttribute ("DataRate", StringValue (SRC_TO_ROUTER_BW));
  p2p.SetChannelAttribute ("Delay", StringValue (del));
  p2p.SetDeviceAttribute ("Mtu", UintegerValue (mtu));
  NetDeviceContainer devices1 = p2p.Install (n0Ton1);

  // Router to Client.
  p2p.SetDeviceAttribute ("DataRate", StringValue (routerToDstBWStr));
  p2p.SetChannelAttribute ("Delay", StringValue (del));
  p2p.SetDeviceAttribute ("Mtu", UintegerValue (mtu));
  p2p.SetQueue ("ns3::DropTailQueue", "MaxSize", QueueSizeValue (que));
  NetDeviceContainer devices2 = p2p.Install (n1Ton2);

  /////////////////////////////////////////
  // Install Internet stack.
  NS_LOG_INFO ("Installing Internet stack.");
  InternetStackHelper internet;
  internet.Install (nodes);

  /////////////////////////////////////////
  // Add IP addresses.
  NS_LOG_INFO ("Assigning IP Addresses.");
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i0i1 = ipv4.Assign (devices1);

  ipv4.SetBase ("191.168.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i1i2 = ipv4.Assign (devices2);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  /////////////////////////////////////////
  // Create flows.
  NS_LOG_INFO ("Creating flows.");
  uint32_t port = 101;
  for (uint32_t i = 0; i < unfairFlows; ++i) {
    sinks.push_back (CreateFlow (port + i, i1i2, nodes, durS, packet_size, "ns3::TcpBbr"));
  }

  for (uint32_t i = 0; i < otherFlows; ++i) {
    sinks.push_back (CreateFlow (port + otherFlows + i, i1i2, nodes, durS, packet_size, otherProto));
  }

  /////////////////////////////////////////
  // Setup tracing (as appropriate).
  NS_LOG_INFO ("Configuring tracing.");
  std::stringstream detailsSs;
  detailsSs <<
    bw << "-" <<
    rttUs << "us-" <<
    queP << "p-" <<
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
    p2p.EnableAsciiAll (ath.CreateFileStream (traceName.str ()));
  }
  if (pcap) {
    NS_LOG_INFO ("Enabling pcap files.");
    std::stringstream pcapName;
    pcapName << outDir << "/" << details;
    p2p.EnablePcapAll (pcapName.str (), true);
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
