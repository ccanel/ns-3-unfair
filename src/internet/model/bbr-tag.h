
#pragma once

#include "ns3/type-id.h"
#include "ns3/tcp-header.h"
#include "ns3/uinteger.h"

namespace ns3 {

class BbrTag : public Tag {
 public:
  BbrTag () = default;
  BbrTag (Time _sndTime, bool _isBbr) : sndTime (_sndTime), isBbr (_isBbr) {}

  static TypeId
    GetTypeId (void)
  {
    static TypeId tid = TypeId ("ns3::BbrTag")
      .SetParent<Tag> ()
      .AddConstructor<BbrTag> ()
      ;
    return tid;
  }

  TypeId
    GetInstanceTypeId (void) const
  {
    return GetTypeId ();
  }

  uint32_t
    GetSerializedSize (void) const
  {
    return sizeof (uint64_t) + sizeof (uint8_t);
  }

  void
    Serialize (TagBuffer i) const
  {
    i.WriteU64 (*((uint64_t*) &sndTime));
    i.WriteU8 ((uint8_t) isBbr);
  }

  void
    Deserialize (TagBuffer i)
  {
    uint64_t tmp = i.ReadU64 ();
    sndTime = *((Time*)& tmp);
    isBbr = (bool) i.ReadU8 ();
  }

  void
    Print (std::ostream &os) const
  {
    os << "sndTime=" << sndTime << ",isBbr=" << isBbr;
  }

  Time sndTime {Seconds (0)};
  bool isBbr         {false};
};

} // namespace ns3
