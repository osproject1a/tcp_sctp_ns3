/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007 Georgia Tech Research Corporation
 * Copyright (c) 2010 Adrian Sai-wah Tam
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Adrian Sai-wah Tam <adrian.sw.tam@gmail.com>
 */

#define NS_LOG_APPEND_CONTEXT \
  if (m_node) { std::clog << Simulator::Now ().GetSeconds () << " [node " << m_node->GetId () << "] "; }

#include "ns3/abort.h"
#include "ns3/node.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/log.h"
#include "ns3/ipv4.h"
#include "ns3/ipv6.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv6-route.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv6-routing-protocol.h"
#include "ns3/simulation-singleton.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/trace-source-accessor.h"
#include "sctp-socket-base.h"
#include "sctp-l4-protocol.h"
/*
#include "ipv4-end-point.h"

#include "ipv6-l3-protocol.h"
*/
//#include "ipv6-end-point.h"
#include "ns3/internet-module.h"
#include "sctp-header.h"
#include "sctp-rtt-estimator.h"

#include <algorithm>

NS_LOG_COMPONENT_DEFINE ("SctpSocketBase");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (SctpSocketBase);

TypeId
SctpSocketBase::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SctpSocketBase")
    .SetParent<SctpSocket> ()
//    .AddAttribute ("SctpState", "State in SCTP state machine",
//                   TypeId::ATTR_GET,
//                   EnumValue (SCTP_CLOSED),
//                   MakeEnumAccessor (&SctpSocketBase::m_state),
//                   MakeEnumChecker (SCTP_CLOSED, "Closed"))
    .AddAttribute ("MaxSegLifetime",
                   "Maximum segment lifetime in seconds, use for SCTP_TIME_WAIT state transition to SCTP_CLOSED state",
                   DoubleValue (120), /* RFC793 says MSL=2 minutes*/
                   MakeDoubleAccessor (&SctpSocketBase::m_msl),
                   MakeDoubleChecker<double> (0))
    .AddAttribute ("MaxWindowSize", "Max size of advertised window",
                   UintegerValue (65535),
                   MakeUintegerAccessor (&SctpSocketBase::m_maxWinSize),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("IcmpCallback", "Callback invoked whenever an icmp error is received on this socket.",
                   CallbackValue (),
                   MakeCallbackAccessor (&SctpSocketBase::m_icmpCallback),
                   MakeCallbackChecker ())
    .AddAttribute ("IcmpCallback6", "Callback invoked whenever an icmpv6 error is received on this socket.",
                   CallbackValue (),
                   MakeCallbackAccessor (&SctpSocketBase::m_icmpCallback6),
                   MakeCallbackChecker ())                   
    .AddTraceSource ("RTO",
                     "Retransmission timeout",
                     MakeTraceSourceAccessor (&SctpSocketBase::m_rto))
    .AddTraceSource ("RTT",
                     "Last RTT sample",
                     MakeTraceSourceAccessor (&SctpSocketBase::m_lastRtt))
    .AddTraceSource ("NextTxSequence",
                     "Next sequence number to send (SND.NXT)",
                     MakeTraceSourceAccessor (&SctpSocketBase::m_nextTxSequence))
    .AddTraceSource ("HighestSequence",
                     "Highest sequence number ever sent in socket's life time",
                     MakeTraceSourceAccessor (&SctpSocketBase::m_highTxMark))
    .AddTraceSource ("State",
                     "SCTP state",
                     MakeTraceSourceAccessor (&SctpSocketBase::m_state))
    .AddTraceSource ("RWND",
                     "Remote side's flow control window",
                     MakeTraceSourceAccessor (&SctpSocketBase::m_rWnd))
  ;
  return tid;
}

SctpSocketBase::SctpSocketBase (void)
  : m_dupAckCount (0),
    m_delAckCount (0),
    m_endPoint (0),
    m_endPoint6 (0),
    m_node (0),
    m_sctp (0),
    m_rtt (0),
    m_nextTxSequence (0),
    // Change this for non-zero initial sequence number
    m_highTxMark (0),
    m_rxBuffer (0),
    m_txBuffer (0),
    m_state (SCTP_CLOSED),
    m_errno (ERROR_NOTERROR),
    m_closeNotified (false),
    m_closeOnEmpty (false),
    m_shutdownSend (false),
    m_shutdownRecv (false),
    m_connected (false),
    m_segmentSize (0),
    // For attribute initialization consistency (quiet valgrind)
    m_rWnd (0)
{
  NS_LOG_FUNCTION (this);
}

SctpSocketBase::SctpSocketBase (const SctpSocketBase& sock)
  : SctpSocket (sock),
    //copy object::m_tid and socket::callbacks
    m_dupAckCount (sock.m_dupAckCount),
    m_delAckCount (0),
    m_delAckMaxCount (sock.m_delAckMaxCount),
    m_noDelay (sock.m_noDelay),
    m_cnRetries (sock.m_cnRetries),
    m_delAckTimeout (sock.m_delAckTimeout),
    m_persistTimeout (sock.m_persistTimeout),
    m_cnTimeout (sock.m_cnTimeout),
    m_endPoint (0),
    m_endPoint6 (0),
    m_node (sock.m_node),
    m_sctp (sock.m_sctp),
    m_rtt (0),
    m_nextTxSequence (sock.m_nextTxSequence),
    m_highTxMark (sock.m_highTxMark),
    m_rxBuffer (sock.m_rxBuffer),
    m_txBuffer (sock.m_txBuffer),
    m_state (sock.m_state),
    m_errno (sock.m_errno),
    m_closeNotified (sock.m_closeNotified),
    m_closeOnEmpty (sock.m_closeOnEmpty),
    m_shutdownSend (sock.m_shutdownSend),
    m_shutdownRecv (sock.m_shutdownRecv),
    m_connected (sock.m_connected),
    m_msl (sock.m_msl),
    m_segmentSize (sock.m_segmentSize),
    m_maxWinSize (sock.m_maxWinSize),
    m_rWnd (sock.m_rWnd)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
  // Copy the rtt estimator if it is set
  if (sock.m_rtt)
    {
      m_rtt = sock.m_rtt->Copy ();
    }
  // Reset all callbacks to null
  Callback<void, Ptr< Socket > > vPS = MakeNullCallback<void, Ptr<Socket> > ();
  Callback<void, Ptr<Socket>, const Address &> vPSA = MakeNullCallback<void, Ptr<Socket>, const Address &> ();
  Callback<void, Ptr<Socket>, uint32_t> vPSUI = MakeNullCallback<void, Ptr<Socket>, uint32_t> ();
  SetConnectCallback (vPS, vPS);
  SetDataSentCallback (vPSUI);
  SetSendCallback (vPSUI);
  SetRecvCallback (vPS);
}

SctpSocketBase::~SctpSocketBase (void)
{
  NS_LOG_FUNCTION (this);
  m_node = 0;
  if (m_endPoint != 0)
    {
      NS_ASSERT (m_sctp != 0);
      /*
       * Upon Bind, an Ipv4Endpoint is allocated and set to m_endPoint, and
       * DestroyCallback is set to SctpSocketBase::Destroy. If we called
       * m_sctp->DeAllocate, it wil destroy its Ipv4EndpointDemux::DeAllocate,
       * which in turn destroys my m_endPoint, and in turn invokes
       * SctpSocketBase::Destroy to nullify m_node, m_endPoint, and m_sctp.
       */
      NS_ASSERT (m_endPoint != 0);
      m_sctp->DeAllocate (m_endPoint);
      NS_ASSERT (m_endPoint == 0);
    }
  if (m_endPoint6 != 0)
    {
      NS_ASSERT (m_sctp != 0);
      NS_ASSERT (m_endPoint6 != 0);
      m_sctp->DeAllocate (m_endPoint6);
      NS_ASSERT (m_endPoint6 == 0);
    }
  m_sctp = 0;
  CancelAllTimers ();
}

/** Associate a node with this SCTP socket */
void
SctpSocketBase::SetNode (Ptr<Node> node)
{
  m_node = node;
}

/** Associate the L4 protocol (e.g. mux/demux) with this socket */
void
SctpSocketBase::SetSctp (Ptr<SctpL4Protocol> sctp)
{
  m_sctp = sctp;
}

/** Set an RTT estimator with this socket */
void
SctpSocketBase::SetRtt (Ptr<Sctp_RttEstimator> rtt)
{
  m_rtt = rtt;
}

/** Inherit from Socket class: Returns error code */
enum Socket::SocketErrno
SctpSocketBase::GetErrno (void) const
{
  return m_errno;
}

/** Inherit from Socket class: Returns socket type, NS3_SOCK_STREAM */
enum Socket::SocketType
SctpSocketBase::GetSocketType (void) const
{
  return NS3_SOCK_STREAM;
}

/** Inherit from Socket class: Returns associated node */
Ptr<Node>
SctpSocketBase::GetNode (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_node;
}

/** Inherit from Socket class: Bind socket to an end-point in SctpL4Protocol */
int
SctpSocketBase::Bind (void)
{
  NS_LOG_FUNCTION (this);
  m_endPoint = m_sctp->Allocate ();
  if (0 == m_endPoint)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }
  m_sctp->m_sockets.push_back (this);
  return SetupCallback ();
}

int
SctpSocketBase::Bind6 (void)
{
  NS_LOG_FUNCTION (this);
  m_endPoint6 = m_sctp->Allocate6 ();
  if (0 == m_endPoint6)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }
  m_sctp->m_sockets.push_back (this);
  return SetupCallback ();
}

/** Inherit from Socket class: Bind socket (with specific address) to an end-point in SctpL4Protocol */
int
SctpSocketBase::Bind (const Address &address)
{
  NS_LOG_FUNCTION (this << address);
  if (InetSocketAddress::IsMatchingType (address))
    {
      InetSocketAddress transport = InetSocketAddress::ConvertFrom (address);
      Ipv4Address ipv4 = transport.GetIpv4 ();
      uint16_t port = transport.GetPort ();
      if (ipv4 == Ipv4Address::GetAny () && port == 0)
        {
          m_endPoint = m_sctp->Allocate ();
        }
      else if (ipv4 == Ipv4Address::GetAny () && port != 0)
        {
          m_endPoint = m_sctp->Allocate (port);
        }
      else if (ipv4 != Ipv4Address::GetAny () && port == 0)
        {
          m_endPoint = m_sctp->Allocate (ipv4);
        }
      else if (ipv4 != Ipv4Address::GetAny () && port != 0)
        {
          m_endPoint = m_sctp->Allocate (ipv4, port);
        }
      if (0 == m_endPoint)
        {
          m_errno = port ? ERROR_ADDRINUSE : ERROR_ADDRNOTAVAIL;
          return -1;
        }
    }
  else if (Inet6SocketAddress::IsMatchingType (address))
    {
      Inet6SocketAddress transport = Inet6SocketAddress::ConvertFrom (address);
      Ipv6Address ipv6 = transport.GetIpv6 ();
      uint16_t port = transport.GetPort ();
      if (ipv6 == Ipv6Address::GetAny () && port == 0)
        {
          m_endPoint6 = m_sctp->Allocate6 ();
        }
      else if (ipv6 == Ipv6Address::GetAny () && port != 0)
        {
          m_endPoint6 = m_sctp->Allocate6 (port);
        }
      else if (ipv6 != Ipv6Address::GetAny () && port == 0)
        {
          m_endPoint6 = m_sctp->Allocate6 (ipv6);
        }
      else if (ipv6 != Ipv6Address::GetAny () && port != 0)
        {
          m_endPoint6 = m_sctp->Allocate6 (ipv6, port);
        }
      if (0 == m_endPoint6)
        {
          m_errno = port ? ERROR_ADDRINUSE : ERROR_ADDRNOTAVAIL;
          return -1;
        }
    }
  else
    {
      m_errno = ERROR_INVAL;
      return -1;
    }
  m_sctp->m_sockets.push_back (this);
  NS_LOG_LOGIC ("SctpSocketBase " << this << " got an endpoint: " << m_endPoint);

  return SetupCallback ();
}

/** Inherit from Socket class: Initiate connection to a remote address:port */
int
SctpSocketBase::Connect (const Address & address)
{
  NS_LOG_FUNCTION (this << address);

  // If haven't do so, Bind() this socket first
  if (InetSocketAddress::IsMatchingType (address) && m_endPoint6 == 0)
    {
      if (m_endPoint == 0)
        {
          if (Bind () == -1)
            {
              NS_ASSERT (m_endPoint == 0);
              return -1; // Bind() failed
            }
          NS_ASSERT (m_endPoint != 0);
        }
      InetSocketAddress transport = InetSocketAddress::ConvertFrom (address);
      m_endPoint->SetPeer (transport.GetIpv4 (), transport.GetPort ());
      m_endPoint6 = 0;

      // Get the appropriate local address and port number from the routing protocol and set up endpoint
      if (SetupEndpoint () != 0)
        { // Route to destination does not exist
          return -1;
        }
    }
  else if (Inet6SocketAddress::IsMatchingType (address)  && m_endPoint == 0)
    {
      // If we are operating on a v4-mapped address, translate the address to
      // a v4 address and re-call this function
      Inet6SocketAddress transport = Inet6SocketAddress::ConvertFrom (address);
      Ipv6Address v6Addr = transport.GetIpv6 ();
      if (v6Addr.IsIpv4MappedAddress () == true)
        {
          Ipv4Address v4Addr = v6Addr.GetIpv4MappedAddress ();
          return Connect (InetSocketAddress (v4Addr, transport.GetPort ()));
        }

      if (m_endPoint6 == 0)
        {
          if (Bind6 () == -1)
            {
              NS_ASSERT (m_endPoint6 == 0);
              return -1; // Bind() failed
            }
          NS_ASSERT (m_endPoint6 != 0);
        }
      m_endPoint6->SetPeer (v6Addr, transport.GetPort ());
      m_endPoint = 0;

      // Get the appropriate local address and port number from the routing protocol and set up endpoint
      if (SetupEndpoint6 () != 0)
        { // Route to destination does not exist
          return -1;
        }
    }
  else
    {
      m_errno = ERROR_INVAL;
      return -1;
    }

  // Re-initialize parameters in case this socket is being reused after CLOSE
  m_rtt->Reset ();
  m_cnCount = m_cnRetries;

  // DoConnect() will do state-checking and send a SYN packet
  return DoConnect ();
}

/** Inherit from Socket class: Listen on the endpoint for an incoming connection */
int
SctpSocketBase::Listen (void)
{
  NS_LOG_FUNCTION (this);
  // Linux quits EINVAL if we're not in SCTP_CLOSED state, so match what they do
  if (m_state != SCTP_CLOSED)
    {
      m_errno = ERROR_INVAL;
      return -1;
    }
  // In other cases, set the state to SCTP_LISTEN and done
  NS_LOG_INFO ("SCTP_CLOSED -> SCTP_LISTEN");
  m_state = SCTP_LISTEN;
  return 0;
}

/** Inherit from Socket class: Kill this socket and signal the peer (if any) */
int
SctpSocketBase::Close (void)
{
  NS_LOG_FUNCTION (this);
  // First we check to see if there is any unread rx data
  // Bug number 426 claims we should send reset in this case.
  if (m_rxBuffer.Size () != 0)
    {
      SendRST ();
      return 0;
    }
  if (m_txBuffer.SizeFromSequence (m_nextTxSequence) > 0)
    { // App close with pending data must wait until all data transmitted
      if (m_closeOnEmpty == false)
        {
          m_closeOnEmpty = true;
          NS_LOG_INFO ("Socket " << this << " deferring close, state " << SctpStateName[m_state]);
        }
      return 0;
    }
  return DoClose ();
}

/** Inherit from Socket class: Signal a termination of send */
int
SctpSocketBase::ShutdownSend (void)
{
  NS_LOG_FUNCTION (this);
  m_shutdownSend = true;
  return 0;
}

/** Inherit from Socket class: Signal a termination of receive */
int
SctpSocketBase::ShutdownRecv (void)
{
  NS_LOG_FUNCTION (this);
  m_shutdownRecv = true;
  return 0;
}

/** Inherit from Socket class: Send a packet. Parameter flags is not used.
    Packet has no SCTP header. Invoked by upper-layer application */
int
SctpSocketBase::Send (Ptr<Packet> p, uint32_t flags)
{
  NS_LOG_FUNCTION (this << p);
  NS_ABORT_MSG_IF (flags, "use of flags is not supported in SctpSocketBase::Send()");
  if (m_state == SCTP_ESTABLISHED || m_state == SCTP_SYN_SENT || m_state == SCTP_CLOSE_WAIT)
    {
      // Store the packet into Tx buffer
      if (!m_txBuffer.Add (p))
        { // TxBuffer overflow, send failed
          m_errno = ERROR_MSGSIZE;
          return -1;
        }
      // Submit the data to lower layers
      NS_LOG_LOGIC ("txBufSize=" << m_txBuffer.Size () << " state " << SctpStateName[m_state]);
      if (m_state == SCTP_ESTABLISHED || m_state == SCTP_CLOSE_WAIT)
        { // Try to send the data out
          SendPendingData (m_connected);
        }
      return p->GetSize ();
    }
  else
    { // Connection not established yet
      m_errno = ERROR_NOTCONN;
      return -1; // Send failure
    }
}

/** Inherit from Socket class: In SctpSocketBase, it is same as Send() call */
int
SctpSocketBase::SendTo (Ptr<Packet> p, uint32_t flags, const Address &address)
{
  return Send (p, flags); // SendTo() and Send() are the same
}

/** Inherit from Socket class: Return data to upper-layer application. Parameter flags
    is not used. Data is returned as a packet of size no larger than maxSize */
Ptr<Packet>
SctpSocketBase::Recv (uint32_t maxSize, uint32_t flags)
{
  NS_LOG_FUNCTION (this);
  NS_ABORT_MSG_IF (flags, "use of flags is not supported in SctpSocketBase::Recv()");
  if (m_rxBuffer.Size () == 0 && m_state == SCTP_CLOSE_WAIT)
    {
      return Create<Packet> (); // Send EOF on connection close
    }
  Ptr<Packet> outPacket = m_rxBuffer.Extract (maxSize);
  if (outPacket != 0 && outPacket->GetSize () != 0)
    {
      SocketAddressTag tag;
      if (m_endPoint != 0)
        {
          tag.SetAddress (InetSocketAddress (m_endPoint->GetPeerAddress (), m_endPoint->GetPeerPort ()));
        }
      else if (m_endPoint6 != 0)
        {
          tag.SetAddress (Inet6SocketAddress (m_endPoint6->GetPeerAddress (), m_endPoint6->GetPeerPort ()));
        }
      outPacket->AddPacketTag (tag);
    }
  return outPacket;
}

/** Inherit from Socket class: Recv and return the remote's address */
Ptr<Packet>
SctpSocketBase::RecvFrom (uint32_t maxSize, uint32_t flags, Address &fromAddress)
{
  NS_LOG_FUNCTION (this << maxSize << flags);
  Ptr<Packet> packet = Recv (maxSize, flags);
  // Null packet means no data to read, and an empty packet indicates EOF
  if (packet != 0 && packet->GetSize () != 0)
    {
      if (m_endPoint != 0)
        {
          fromAddress = InetSocketAddress (m_endPoint->GetPeerAddress (), m_endPoint->GetPeerPort ());
        }
      else if (m_endPoint6 != 0)
        {
          fromAddress = Inet6SocketAddress (m_endPoint6->GetPeerAddress (), m_endPoint6->GetPeerPort ());
        }
      else
        {
          fromAddress = InetSocketAddress (Ipv4Address::GetZero (), 0);
        }
    }
  return packet;
}

/** Inherit from Socket class: Get the max number of bytes an app can send */
uint32_t
SctpSocketBase::GetTxAvailable (void) const
{
  NS_LOG_FUNCTION (this);
  return m_txBuffer.Available ();
}

/** Inherit from Socket class: Get the max number of bytes an app can read */
uint32_t
SctpSocketBase::GetRxAvailable (void) const
{
  NS_LOG_FUNCTION (this);
  return m_rxBuffer.Available ();
}

/** Inherit from Socket class: Return local address:port */
int
SctpSocketBase::GetSockName (Address &address) const
{
  NS_LOG_FUNCTION (this);
  if (m_endPoint != 0)
    {
      address = InetSocketAddress (m_endPoint->GetLocalAddress (), m_endPoint->GetLocalPort ());
    }
  else if (m_endPoint6 != 0)
    {
      address = Inet6SocketAddress (m_endPoint6->GetLocalAddress (), m_endPoint6->GetLocalPort ());
    }
  else
    { // It is possible to call this method on a socket without a name
      // in which case, behavior is unspecified
      // Should this return an InetSocketAddress or an Inet6SocketAddress?
      address = InetSocketAddress (Ipv4Address::GetZero (), 0);
    }
  return 0;
}

/** Inherit from Socket class: Bind this socket to the specified NetDevice */
void
SctpSocketBase::BindToNetDevice (Ptr<NetDevice> netdevice)
{
  NS_LOG_FUNCTION (netdevice);
  Socket::BindToNetDevice (netdevice); // Includes sanity check
  if (m_endPoint == 0 && m_endPoint6 == 0)
    {
      if (Bind () == -1)
        {
          NS_ASSERT ((m_endPoint == 0 && m_endPoint6 == 0));
          return;
        }
      NS_ASSERT ((m_endPoint != 0 && m_endPoint6 != 0));
    }

  if (m_endPoint != 0)
    {
      m_endPoint->BindToNetDevice (netdevice);
    }
  // No BindToNetDevice() for Ipv6EndPoint
  return;
}

/** Clean up after Bind. Set up callback functions in the end-point. */
int
SctpSocketBase::SetupCallback (void)
{
  NS_LOG_FUNCTION (this);

  if (m_endPoint == 0 && m_endPoint6 == 0)
    {
      return -1;
    }
  if (m_endPoint != 0)
    {
      m_endPoint->SetRxCallback (MakeCallback (&SctpSocketBase::ForwardUp, Ptr<SctpSocketBase> (this)));
      m_endPoint->SetIcmpCallback (MakeCallback (&SctpSocketBase::ForwardIcmp, Ptr<SctpSocketBase> (this)));
      m_endPoint->SetDestroyCallback (MakeCallback (&SctpSocketBase::Destroy, Ptr<SctpSocketBase> (this)));
    }
  if (m_endPoint6 != 0)
    {
      m_endPoint6->SetRxCallback (MakeCallback (&SctpSocketBase::ForwardUp6, Ptr<SctpSocketBase> (this)));
      m_endPoint6->SetIcmpCallback (MakeCallback (&SctpSocketBase::ForwardIcmp6, Ptr<SctpSocketBase> (this)));
      m_endPoint6->SetDestroyCallback (MakeCallback (&SctpSocketBase::Destroy6, Ptr<SctpSocketBase> (this)));
    }

  return 0;
}

/** Perform the real connection tasks: Send SYN if allowed, RST if invalid */
int
SctpSocketBase::DoConnect (void)
{
  NS_LOG_FUNCTION (this);

  // A new connection is allowed only if this socket does not have a connection
  if (m_state == SCTP_CLOSED || m_state == SCTP_LISTEN || m_state == SCTP_SYN_SENT || m_state == SCTP_LAST_ACK || m_state == SCTP_CLOSE_WAIT)
    { // send a SYN packet and change state into SCTP_SYN_SENT
      SendEmptyPacket (SctpHeader::SYN);
      NS_LOG_INFO (SctpStateName[m_state] << " -> SCTP_SYN_SENT");
      m_state = SCTP_SYN_SENT;
    }
  else if (m_state != SCTP_TIME_WAIT)
    { // In states SCTP_SYN_RCVD, SCTP_ESTABLISHED, SCTP_FIN_WAIT_1, SCTP_FIN_WAIT_2, and SCTP_CLOSING, an connection
      // exists. We send RST, tear down everything, and close this socket.
      SendRST ();
      CloseAndNotify ();
    }
  return 0;
}

/** Do the action to close the socket. Usually send a packet with appropriate
    flags depended on the current m_state. */
int
SctpSocketBase::DoClose (void)
{
  NS_LOG_FUNCTION (this);
  switch (m_state)
    {
    case SCTP_SYN_RCVD:
    case SCTP_ESTABLISHED:
      // send FIN to close the peer
      SendEmptyPacket (SctpHeader::FIN);
      NS_LOG_INFO ("SCTP_ESTABLISHED -> SCTP_FIN_WAIT_1");
      m_state = SCTP_FIN_WAIT_1;
      break;
    case SCTP_CLOSE_WAIT:
      // send FIN+ACK to close the peer
      SendEmptyPacket (SctpHeader::FIN | SctpHeader::ACK);
      NS_LOG_INFO ("SCTP_CLOSE_WAIT -> SCTP_LAST_ACK");
      m_state = SCTP_LAST_ACK;
      break;
    case SCTP_SYN_SENT:
    case SCTP_CLOSING:
      // Send RST if application closes in SCTP_SYN_SENT and SCTP_CLOSING
      SendRST ();
      CloseAndNotify ();
      break;
    case SCTP_LISTEN:
    case SCTP_LAST_ACK:
      // In these three states, move to SCTP_CLOSED and tear down the end point
      CloseAndNotify ();
      break;
    case SCTP_CLOSED:
    case SCTP_FIN_WAIT_1:
    case SCTP_FIN_WAIT_2:
    case SCTP_TIME_WAIT:
    default: /* mute compiler */
      // Do nothing in these four states
      break;
    }
  return 0;
}

/** Peacefully close the socket by notifying the upper layer and deallocate end point */
void
SctpSocketBase::CloseAndNotify (void)
{
  NS_LOG_FUNCTION (this);

  if (!m_closeNotified)
    {
      NotifyNormalClose ();
    }
  if (m_state != SCTP_TIME_WAIT)
    {
      DeallocateEndPoint ();
    }
  m_closeNotified = true;
  NS_LOG_INFO (SctpStateName[m_state] << " -> SCTP_CLOSED");
  CancelAllTimers ();
  m_state = SCTP_CLOSED;
}


/** Tell if a sequence number range is out side the range that my rx buffer can
    accpet */
bool
SctpSocketBase::OutOfRange (SequenceNumber32 head, SequenceNumber32 tail) const
{
  if (m_state == SCTP_LISTEN || m_state == SCTP_SYN_SENT || m_state == SCTP_SYN_RCVD)
    { // Rx buffer in these states are not initialized.
      return false;
    }
  if (m_state == SCTP_LAST_ACK || m_state == SCTP_CLOSING || m_state == SCTP_CLOSE_WAIT)
    { // In SCTP_LAST_ACK and SCTP_CLOSING states, it only wait for an ACK and the
      // sequence number must equals to m_rxBuffer.NextRxSequence ()
      return (m_rxBuffer.NextRxSequence () != head);
    }

  // In all other cases, check if the sequence number is in range
  return (tail < m_rxBuffer.NextRxSequence () || m_rxBuffer.MaxRxSequence () <= head);
}

/** Function called by the L3 protocol when it received a packet to pass on to
    the SCTP. This function is registered as the "RxCallback" function in
    SetupCallback(), which invoked by Bind(), and CompleteFork() */
void
SctpSocketBase::ForwardUp (Ptr<Packet> packet, Ipv4Header header, uint16_t port,
                          Ptr<Ipv4Interface> incomingInterface)
{
  DoForwardUp (packet, header, port, incomingInterface);
}

void
SctpSocketBase::ForwardUp6 (Ptr<Packet> packet, Ipv6Header header, uint16_t port)
{
  DoForwardUp (packet, header, port);
}

void
SctpSocketBase::ForwardIcmp (Ipv4Address icmpSource, uint8_t icmpTtl,
                            uint8_t icmpType, uint8_t icmpCode,
                            uint32_t icmpInfo)
{
  NS_LOG_FUNCTION (this << icmpSource << (uint32_t)icmpTtl << (uint32_t)icmpType <<
                   (uint32_t)icmpCode << icmpInfo);
  if (!m_icmpCallback.IsNull ())
    {
      m_icmpCallback (icmpSource, icmpTtl, icmpType, icmpCode, icmpInfo);
    }
}

void
SctpSocketBase::ForwardIcmp6 (Ipv6Address icmpSource, uint8_t icmpTtl,
                            uint8_t icmpType, uint8_t icmpCode,
                            uint32_t icmpInfo)
{
  NS_LOG_FUNCTION (this << icmpSource << (uint32_t)icmpTtl << (uint32_t)icmpType <<
                   (uint32_t)icmpCode << icmpInfo);
  if (!m_icmpCallback6.IsNull ())
    {
      m_icmpCallback6 (icmpSource, icmpTtl, icmpType, icmpCode, icmpInfo);
    }
}

/** The real function to handle the incoming packet from lower layers. This is
    wrapped by ForwardUp() so that this function can be overloaded by daughter
    classes. */
void
SctpSocketBase::DoForwardUp (Ptr<Packet> packet, Ipv4Header header, uint16_t port,
                            Ptr<Ipv4Interface> incomingInterface)
{
  NS_LOG_LOGIC ("Socket " << this << " forward up " <<
                m_endPoint->GetPeerAddress () <<
                ":" << m_endPoint->GetPeerPort () <<
                " to " << m_endPoint->GetLocalAddress () <<
                ":" << m_endPoint->GetLocalPort ());
  Address fromAddress = InetSocketAddress (header.GetSource (), port);
  Address toAddress = InetSocketAddress (header.GetDestination (), m_endPoint->GetLocalPort ());

  // Peel off SCTP header and do validity checking
  SctpHeader sctpHeader;
  packet->RemoveHeader (sctpHeader);
  if (sctpHeader.GetFlags () & SctpHeader::ACK)
    {
      EstimateRtt (sctpHeader);
    }
  ReadOptions (sctpHeader);

  // Update Rx window size, i.e. the flow control window
  if (m_rWnd.Get () == 0 && sctpHeader.GetWindowSize () != 0)
    { // persist probes end
      NS_LOG_LOGIC (this << " Leaving zerowindow persist state");
      m_persistEvent.Cancel ();
    }
  m_rWnd = sctpHeader.GetWindowSize ();

  // Discard fully out of range data packets
  if (packet->GetSize ()
      && OutOfRange (sctpHeader.GetSequenceNumber (), sctpHeader.GetSequenceNumber () + packet->GetSize ()))
    {
      NS_LOG_LOGIC ("At state " << SctpStateName[m_state] <<
                    " received packet of seq [" << sctpHeader.GetSequenceNumber () <<
                    ":" << sctpHeader.GetSequenceNumber () + packet->GetSize () <<
                    ") out of range [" << m_rxBuffer.NextRxSequence () << ":" <<
                    m_rxBuffer.MaxRxSequence () << ")");
      // Acknowledgement should be sent for all unacceptable packets (RFC793, p.69)
      if (m_state == SCTP_ESTABLISHED && !(sctpHeader.GetFlags () & SctpHeader::RST))
        {
          SendEmptyPacket (SctpHeader::ACK);
        }
      return;
    }

  // SCTP state machine code in different process functions
  // C.f.: sctp_rcv_state_process() in sctp_input.c in Linux kernel
  switch (m_state)
    {
    case SCTP_ESTABLISHED:
      ProcessEstablished (packet, sctpHeader);
      break;
    case SCTP_LISTEN:
      ProcessListen (packet, sctpHeader, fromAddress, toAddress);
      break;
    case SCTP_TIME_WAIT:
      // Do nothing
      break;
    case SCTP_CLOSED:
      // Send RST if the incoming packet is not a RST
      if ((sctpHeader.GetFlags () & ~(SctpHeader::PSH | SctpHeader::URG)) != SctpHeader::RST)
        { // Since m_endPoint is not configured yet, we cannot use SendRST here
          SctpHeader h;
          h.SetFlags (SctpHeader::RST);
          h.SetSequenceNumber (m_nextTxSequence);
          h.SetAckNumber (m_rxBuffer.NextRxSequence ());
          h.SetSourcePort (sctpHeader.GetDestinationPort ());
          h.SetDestinationPort (sctpHeader.GetSourcePort ());
          h.SetWindowSize (AdvertisedWindowSize ());
          AddOptions (h);
          m_sctp->SendPacket (Create<Packet> (), h, header.GetDestination (), header.GetSource (), m_boundnetdevice);
        }
      break;
    case SCTP_SYN_SENT:
      ProcessSynSent (packet, sctpHeader);
      break;
    case SCTP_SYN_RCVD:
      ProcessSynRcvd (packet, sctpHeader, fromAddress, toAddress);
      break;
    case SCTP_FIN_WAIT_1:
    case SCTP_FIN_WAIT_2:
    case SCTP_CLOSE_WAIT:
      ProcessWait (packet, sctpHeader);
      break;
    case SCTP_CLOSING:
      ProcessClosing (packet, sctpHeader);
      break;
    case SCTP_LAST_ACK:
      ProcessLastAck (packet, sctpHeader);
      break;
    default: // mute compiler
      break;
    }
}

void
SctpSocketBase::DoForwardUp (Ptr<Packet> packet, Ipv6Header header, uint16_t port)
{
  NS_LOG_LOGIC ("Socket " << this << " forward up " <<
                m_endPoint6->GetPeerAddress () <<
                ":" << m_endPoint6->GetPeerPort () <<
                " to " << m_endPoint6->GetLocalAddress () <<
                ":" << m_endPoint6->GetLocalPort ());
  Address fromAddress = Inet6SocketAddress (header.GetSourceAddress (), port);
  Address toAddress = Inet6SocketAddress (header.GetDestinationAddress (), m_endPoint6->GetLocalPort ());

  // Peel off SCTP header and do validity checking
  SctpHeader sctpHeader;
  packet->RemoveHeader (sctpHeader);
  if (sctpHeader.GetFlags () & SctpHeader::ACK)
    {
      EstimateRtt (sctpHeader);
    }
  ReadOptions (sctpHeader);

  // Update Rx window size, i.e. the flow control window
  if (m_rWnd.Get () == 0 && sctpHeader.GetWindowSize () != 0)
    { // persist probes end
      NS_LOG_LOGIC (this << " Leaving zerowindow persist state");
      m_persistEvent.Cancel ();
    }
  m_rWnd = sctpHeader.GetWindowSize ();

  // Discard fully out of range packets
  if (packet->GetSize ()
      && OutOfRange (sctpHeader.GetSequenceNumber (), sctpHeader.GetSequenceNumber () + packet->GetSize ()))
    {
      NS_LOG_LOGIC ("At state " << SctpStateName[m_state] <<
                    " received packet of seq [" << sctpHeader.GetSequenceNumber () <<
                    ":" << sctpHeader.GetSequenceNumber () + packet->GetSize () <<
                    ") out of range [" << m_rxBuffer.NextRxSequence () << ":" <<
                    m_rxBuffer.MaxRxSequence () << ")");
      // Acknowledgement should be sent for all unacceptable packets (RFC793, p.69)
      if (m_state == SCTP_ESTABLISHED && !(sctpHeader.GetFlags () & SctpHeader::RST))
        {
          SendEmptyPacket (SctpHeader::ACK);
        }
      return;
    }

  // SCTP state machine code in different process functions
  // C.f.: sctp_rcv_state_process() in sctp_input.c in Linux kernel
  switch (m_state)
    {
    case SCTP_ESTABLISHED:
      ProcessEstablished (packet, sctpHeader);
      break;
    case SCTP_LISTEN:
      ProcessListen (packet, sctpHeader, fromAddress, toAddress);
      break;
    case SCTP_TIME_WAIT:
      // Do nothing
      break;
    case SCTP_CLOSED:
      // Send RST if the incoming packet is not a RST
      if ((sctpHeader.GetFlags () & ~(SctpHeader::PSH | SctpHeader::URG)) != SctpHeader::RST)
        { // Since m_endPoint is not configured yet, we cannot use SendRST here
          SctpHeader h;
          h.SetFlags (SctpHeader::RST);
          h.SetSequenceNumber (m_nextTxSequence);
          h.SetAckNumber (m_rxBuffer.NextRxSequence ());
          h.SetSourcePort (sctpHeader.GetDestinationPort ());
          h.SetDestinationPort (sctpHeader.GetSourcePort ());
          h.SetWindowSize (AdvertisedWindowSize ());
          AddOptions (h);
          m_sctp->SendPacket (Create<Packet> (), h, header.GetDestinationAddress (), header.GetSourceAddress (), m_boundnetdevice);
        }
      break;
    case SCTP_SYN_SENT:
      ProcessSynSent (packet, sctpHeader);
      break;
    case SCTP_SYN_RCVD:
      ProcessSynRcvd (packet, sctpHeader, fromAddress, toAddress);
      break;
    case SCTP_FIN_WAIT_1:
    case SCTP_FIN_WAIT_2:
    case SCTP_CLOSE_WAIT:
      ProcessWait (packet, sctpHeader);
      break;
    case SCTP_CLOSING:
      ProcessClosing (packet, sctpHeader);
      break;
    case SCTP_LAST_ACK:
      ProcessLastAck (packet, sctpHeader);
      break;
    default: // mute compiler
      break;
    }
}

/** Received a packet upon SCTP_ESTABLISHED state. This function is mimicking the
    role of sctp_rcv_established() in sctp_input.c in Linux kernel. */
void
SctpSocketBase::ProcessEstablished (Ptr<Packet> packet, const SctpHeader& sctpHeader)
{
  NS_LOG_FUNCTION (this << sctpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t sctpflags = sctpHeader.GetFlags () & ~(SctpHeader::PSH | SctpHeader::URG);

  // Different flags are different events
  if (sctpflags == SctpHeader::ACK)
    {
      ReceivedAck (packet, sctpHeader);
    }
  else if (sctpflags == SctpHeader::SYN)
    { // Received SYN, old NS-3 behaviour is to set state to SCTP_SYN_RCVD and
      // respond with a SYN+ACK. But it is not a legal state transition as of
      // RFC793. Thus this is ignored.
    }
  else if (sctpflags == (SctpHeader::SYN | SctpHeader::ACK))
    { // No action for received SYN+ACK, it is probably a duplicated packet
    }
  else if (sctpflags == SctpHeader::FIN || sctpflags == (SctpHeader::FIN | SctpHeader::ACK))
    { // Received FIN or FIN+ACK, bring down this socket nicely
      PeerClose (packet, sctpHeader);
    }
  else if (sctpflags == 0)
    { // No flags means there is only data
      ReceivedData (packet, sctpHeader);
      if (m_rxBuffer.Finished ())
        {
          PeerClose (packet, sctpHeader);
        }
    }
  else
    { // Received RST or the SCTP flags is invalid, in either case, terminate this socket
      if (sctpflags != SctpHeader::RST)
        { // this must be an invalid flag, send reset
          NS_LOG_LOGIC ("Illegal flag " << sctpflags << " received. Reset packet is sent.");
          SendRST ();
        }
      CloseAndNotify ();
    }
}

/** Process the newly received ACK */
void
SctpSocketBase::ReceivedAck (Ptr<Packet> packet, const SctpHeader& sctpHeader)
{
  NS_LOG_FUNCTION (this << sctpHeader);

  // Received ACK. Compare the ACK number against highest unacked seqno
  if (0 == (sctpHeader.GetFlags () & SctpHeader::ACK))
    { // Ignore if no ACK flag
    }
  else if (sctpHeader.GetAckNumber () < m_txBuffer.HeadSequence ())
    { // Case 1: Old ACK, ignored.
      NS_LOG_LOGIC ("Ignored ack of " << sctpHeader.GetAckNumber ());
    }
  else if (sctpHeader.GetAckNumber () == m_txBuffer.HeadSequence ())
    { // Case 2: Potentially a duplicated ACK
      if (sctpHeader.GetAckNumber () < m_nextTxSequence && packet->GetSize() == 0)
        {
          NS_LOG_LOGIC ("Dupack of " << sctpHeader.GetAckNumber ());
          DupAck (sctpHeader, ++m_dupAckCount);
        }
      // otherwise, the ACK is precisely equal to the nextTxSequence
      NS_ASSERT (sctpHeader.GetAckNumber () <= m_nextTxSequence);
    }
  else if (sctpHeader.GetAckNumber () > m_txBuffer.HeadSequence ())
    { // Case 3: New ACK, reset m_dupAckCount and update m_txBuffer
      NS_LOG_LOGIC ("New ack of " << sctpHeader.GetAckNumber ());
      NewAck (sctpHeader.GetAckNumber ());
      m_dupAckCount = 0;
    }
  // If there is any data piggybacked, store it into m_rxBuffer
  if (packet->GetSize () > 0)
    {
      ReceivedData (packet, sctpHeader);
    }
}

/** Received a packet upon SCTP_LISTEN state. */
void
SctpSocketBase::ProcessListen (Ptr<Packet> packet, const SctpHeader& sctpHeader,
                              const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION (this << sctpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t sctpflags = sctpHeader.GetFlags () & ~(SctpHeader::PSH | SctpHeader::URG);

  // Fork a socket if received a SYN. Do nothing otherwise.
  // C.f.: the SCTP_LISTEN part in sctp_v4_do_rcv() in sctp_ipv4.c in Linux kernel
  if (sctpflags != SctpHeader::SYN)
    {
      return;
    }

  // Call socket's notify function to let the server app know we got a SYN
  // If the server app refuses the connection, do nothing
  if (!NotifyConnectionRequest (fromAddress))
    {
      return;
    }
  // Clone the socket, simulate fork
  Ptr<SctpSocketBase> newSock = Fork ();
  NS_LOG_LOGIC ("Cloned a SctpSocketBase " << newSock);
  Simulator::ScheduleNow (&SctpSocketBase::CompleteFork, newSock,
                          packet, sctpHeader, fromAddress, toAddress);
}

/** Received a packet upon SCTP_SYN_SENT */
void
SctpSocketBase::ProcessSynSent (Ptr<Packet> packet, const SctpHeader& sctpHeader)
{
  NS_LOG_FUNCTION (this << sctpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t sctpflags = sctpHeader.GetFlags () & ~(SctpHeader::PSH | SctpHeader::URG);

  if (sctpflags == 0)
    { // Bare data, accept it and move to SCTP_ESTABLISHED state. This is not a normal behaviour. Remove this?
      NS_LOG_INFO ("SCTP_SYN_SENT -> SCTP_ESTABLISHED");
      m_state = SCTP_ESTABLISHED;
      m_connected = true;
      m_retxEvent.Cancel ();
      m_delAckCount = m_delAckMaxCount;
      ReceivedData (packet, sctpHeader);
      Simulator::ScheduleNow (&SctpSocketBase::ConnectionSucceeded, this);
    }
  else if (sctpflags == SctpHeader::ACK)
    { // Ignore ACK in SCTP_SYN_SENT
    }
  else if (sctpflags == SctpHeader::SYN)
    { // Received SYN, move to SCTP_SYN_RCVD state and respond with SYN+ACK
      NS_LOG_INFO ("SCTP_SYN_SENT -> SCTP_SYN_RCVD");
      m_state = SCTP_SYN_RCVD;
      m_cnCount = m_cnRetries;
      m_rxBuffer.SetNextRxSequence (sctpHeader.GetSequenceNumber () + SequenceNumber32 (1));
      SendEmptyPacket (SctpHeader::SYN | SctpHeader::ACK);
    }
  else if (sctpflags == (SctpHeader::SYN | SctpHeader::ACK)
           && m_nextTxSequence + SequenceNumber32 (1) == sctpHeader.GetAckNumber ())
    { // Handshake completed
      NS_LOG_INFO ("SCTP_SYN_SENT -> SCTP_ESTABLISHED");
      m_state = SCTP_ESTABLISHED;
      m_connected = true;
      m_retxEvent.Cancel ();
      m_rxBuffer.SetNextRxSequence (sctpHeader.GetSequenceNumber () + SequenceNumber32 (1));
      m_highTxMark = ++m_nextTxSequence;
      m_txBuffer.SetHeadSequence (m_nextTxSequence);
      SendEmptyPacket (SctpHeader::ACK);
      SendPendingData (m_connected);
      Simulator::ScheduleNow (&SctpSocketBase::ConnectionSucceeded, this);
      // Always respond to first data packet to speed up the connection.
      // Remove to get the behaviour of old NS-3 code.
      m_delAckCount = m_delAckMaxCount;
    }
  else
    { // Other in-sequence input
      if (sctpflags != SctpHeader::RST)
        { // When (1) rx of FIN+ACK; (2) rx of FIN; (3) rx of bad flags
          NS_LOG_LOGIC ("Illegal flag " << std::hex << static_cast<uint32_t> (sctpflags) << std::dec << " received. Reset packet is sent.");
          SendRST ();
        }
      CloseAndNotify ();
    }
}

/** Received a packet upon SCTP_SYN_RCVD */
void
SctpSocketBase::ProcessSynRcvd (Ptr<Packet> packet, const SctpHeader& sctpHeader,
                               const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION (this << sctpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t sctpflags = sctpHeader.GetFlags () & ~(SctpHeader::PSH | SctpHeader::URG);

  if (sctpflags == 0
      || (sctpflags == SctpHeader::ACK
          && m_nextTxSequence + SequenceNumber32 (1) == sctpHeader.GetAckNumber ()))
    { // If it is bare data, accept it and move to SCTP_ESTABLISHED state. This is
      // possibly due to ACK lost in 3WHS. If in-sequence ACK is received, the
      // handshake is completed nicely.
      NS_LOG_INFO ("SCTP_SYN_RCVD -> SCTP_ESTABLISHED");
      m_state = SCTP_ESTABLISHED;
      m_connected = true;
      m_retxEvent.Cancel ();
      m_highTxMark = ++m_nextTxSequence;
      m_txBuffer.SetHeadSequence (m_nextTxSequence);
      if (m_endPoint)
        {
          m_endPoint->SetPeer (InetSocketAddress::ConvertFrom (fromAddress).GetIpv4 (),
                               InetSocketAddress::ConvertFrom (fromAddress).GetPort ());
        }
      else if (m_endPoint6)
        {
          m_endPoint6->SetPeer (Inet6SocketAddress::ConvertFrom (fromAddress).GetIpv6 (),
                                Inet6SocketAddress::ConvertFrom (fromAddress).GetPort ());
        }
      // Always respond to first data packet to speed up the connection.
      // Remove to get the behaviour of old NS-3 code.
      m_delAckCount = m_delAckMaxCount;
      ReceivedAck (packet, sctpHeader);
      NotifyNewConnectionCreated (this, fromAddress);
      // As this connection is established, the socket is available to send data now
      if (GetTxAvailable () > 0)
        {
          NotifySend (GetTxAvailable ());
        }
    }
  else if (sctpflags == SctpHeader::SYN)
    { // Probably the peer lost my SYN+ACK
      m_rxBuffer.SetNextRxSequence (sctpHeader.GetSequenceNumber () + SequenceNumber32 (1));
      SendEmptyPacket (SctpHeader::SYN | SctpHeader::ACK);
    }
  else if (sctpflags == (SctpHeader::FIN | SctpHeader::ACK))
    {
      if (sctpHeader.GetSequenceNumber () == m_rxBuffer.NextRxSequence ())
        { // In-sequence FIN before connection complete. Set up connection and close.
          m_connected = true;
          m_retxEvent.Cancel ();
          m_highTxMark = ++m_nextTxSequence;
          m_txBuffer.SetHeadSequence (m_nextTxSequence);
          if (m_endPoint)
            {
              m_endPoint->SetPeer (InetSocketAddress::ConvertFrom (fromAddress).GetIpv4 (),
                                   InetSocketAddress::ConvertFrom (fromAddress).GetPort ());
            }
          else if (m_endPoint6)
            {
              m_endPoint6->SetPeer (Inet6SocketAddress::ConvertFrom (fromAddress).GetIpv6 (),
                                    Inet6SocketAddress::ConvertFrom (fromAddress).GetPort ());
            }
          PeerClose (packet, sctpHeader);
        }
    }
  else
    { // Other in-sequence input
      if (sctpflags != SctpHeader::RST)
        { // When (1) rx of SYN+ACK; (2) rx of FIN; (3) rx of bad flags
          NS_LOG_LOGIC ("Illegal flag " << sctpflags << " received. Reset packet is sent.");
          if (m_endPoint)
            {
              m_endPoint->SetPeer (InetSocketAddress::ConvertFrom (fromAddress).GetIpv4 (),
                                   InetSocketAddress::ConvertFrom (fromAddress).GetPort ());
            }
          else if (m_endPoint6)
            {
              m_endPoint6->SetPeer (Inet6SocketAddress::ConvertFrom (fromAddress).GetIpv6 (),
                                    Inet6SocketAddress::ConvertFrom (fromAddress).GetPort ());
            }
          SendRST ();
        }
      CloseAndNotify ();
    }
}

/** Received a packet upon SCTP_CLOSE_WAIT, SCTP_FIN_WAIT_1, or SCTP_FIN_WAIT_2 states */
void
SctpSocketBase::ProcessWait (Ptr<Packet> packet, const SctpHeader& sctpHeader)
{
  NS_LOG_FUNCTION (this << sctpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t sctpflags = sctpHeader.GetFlags () & ~(SctpHeader::PSH | SctpHeader::URG);

  if (packet->GetSize () > 0 && sctpflags != SctpHeader::ACK)
    { // Bare data, accept it
      ReceivedData (packet, sctpHeader);
    }
  else if (sctpflags == SctpHeader::ACK)
    { // Process the ACK, and if in SCTP_FIN_WAIT_1, conditionally move to SCTP_FIN_WAIT_2
      ReceivedAck (packet, sctpHeader);
      if (m_state == SCTP_FIN_WAIT_1 && m_txBuffer.Size () == 0
          && sctpHeader.GetAckNumber () == m_highTxMark + SequenceNumber32 (1))
        { // This ACK corresponds to the FIN sent
          NS_LOG_INFO ("SCTP_FIN_WAIT_1 -> SCTP_FIN_WAIT_2");
          m_state = SCTP_FIN_WAIT_2;
        }
    }
  else if (sctpflags == SctpHeader::FIN || sctpflags == (SctpHeader::FIN | SctpHeader::ACK))
    { // Got FIN, respond with ACK and move to next state
      if (sctpflags & SctpHeader::ACK)
        { // Process the ACK first
          ReceivedAck (packet, sctpHeader);
        }
      m_rxBuffer.SetFinSequence (sctpHeader.GetSequenceNumber ());
    }
  else if (sctpflags == SctpHeader::SYN || sctpflags == (SctpHeader::SYN | SctpHeader::ACK))
    { // Duplicated SYN or SYN+ACK, possibly due to spurious retransmission
      return;
    }
  else
    { // This is a RST or bad flags
      if (sctpflags != SctpHeader::RST)
        {
          NS_LOG_LOGIC ("Illegal flag " << sctpflags << " received. Reset packet is sent.");
          SendRST ();
        }
      CloseAndNotify ();
      return;
    }

  // Check if the close responder sent an in-sequence FIN, if so, respond ACK
  if ((m_state == SCTP_FIN_WAIT_1 || m_state == SCTP_FIN_WAIT_2) && m_rxBuffer.Finished ())
    {
      if (m_state == SCTP_FIN_WAIT_1)
        {
          NS_LOG_INFO ("SCTP_FIN_WAIT_1 -> SCTP_CLOSING");
          m_state = SCTP_CLOSING;
          if (m_txBuffer.Size () == 0
              && sctpHeader.GetAckNumber () == m_highTxMark + SequenceNumber32 (1))
            { // This ACK corresponds to the FIN sent
              TimeWait ();
            }
        }
      else if (m_state == SCTP_FIN_WAIT_2)
        {
          TimeWait ();
        }
      SendEmptyPacket (SctpHeader::ACK);
      if (!m_shutdownRecv)
        {
          NotifyDataRecv ();
        }
    }
}

/** Received a packet upon SCTP_CLOSING */
void
SctpSocketBase::ProcessClosing (Ptr<Packet> packet, const SctpHeader& sctpHeader)
{
  NS_LOG_FUNCTION (this << sctpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t sctpflags = sctpHeader.GetFlags () & ~(SctpHeader::PSH | SctpHeader::URG);

  if (sctpflags == SctpHeader::ACK)
    {
      if (sctpHeader.GetSequenceNumber () == m_rxBuffer.NextRxSequence ())
        { // This ACK corresponds to the FIN sent
          TimeWait ();
        }
    }
  else
    { // SCTP_CLOSING state means simultaneous close, i.e. no one is sending data to
      // anyone. If anything other than ACK is received, respond with a reset.
      if (sctpflags == SctpHeader::FIN || sctpflags == (SctpHeader::FIN | SctpHeader::ACK))
        { // FIN from the peer as well. We can close immediately.
          SendEmptyPacket (SctpHeader::ACK);
        }
      else if (sctpflags != SctpHeader::RST)
        { // Receive of SYN or SYN+ACK or bad flags or pure data
          NS_LOG_LOGIC ("Illegal flag " << sctpflags << " received. Reset packet is sent.");
          SendRST ();
        }
      CloseAndNotify ();
    }
}

/** Received a packet upon SCTP_LAST_ACK */
void
SctpSocketBase::ProcessLastAck (Ptr<Packet> packet, const SctpHeader& sctpHeader)
{
  NS_LOG_FUNCTION (this << sctpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t sctpflags = sctpHeader.GetFlags () & ~(SctpHeader::PSH | SctpHeader::URG);

  if (sctpflags == 0)
    {
      ReceivedData (packet, sctpHeader);
    }
  else if (sctpflags == SctpHeader::ACK)
    {
      if (sctpHeader.GetSequenceNumber () == m_rxBuffer.NextRxSequence ())
        { // This ACK corresponds to the FIN sent. This socket closed peacefully.
          CloseAndNotify ();
        }
    }
  else if (sctpflags == SctpHeader::FIN)
    { // Received FIN again, the peer probably lost the FIN+ACK
      SendEmptyPacket (SctpHeader::FIN | SctpHeader::ACK);
    }
  else if (sctpflags == (SctpHeader::FIN | SctpHeader::ACK) || sctpflags == SctpHeader::RST)
    {
      CloseAndNotify ();
    }
  else
    { // Received a SYN or SYN+ACK or bad flags
      NS_LOG_LOGIC ("Illegal flag " << sctpflags << " received. Reset packet is sent.");
      SendRST ();
      CloseAndNotify ();
    }
}

/** Peer sent me a FIN. Remember its sequence in rx buffer. */
void
SctpSocketBase::PeerClose (Ptr<Packet> p, const SctpHeader& sctpHeader)
{
  NS_LOG_FUNCTION (this << sctpHeader);

  // Ignore all out of range packets
  if (sctpHeader.GetSequenceNumber () < m_rxBuffer.NextRxSequence ()
      || sctpHeader.GetSequenceNumber () > m_rxBuffer.MaxRxSequence ())
    {
      return;
    }
  // For any case, remember the FIN position in rx buffer first
  m_rxBuffer.SetFinSequence (sctpHeader.GetSequenceNumber () + SequenceNumber32 (p->GetSize ()));
  NS_LOG_LOGIC ("Accepted FIN at seq " << sctpHeader.GetSequenceNumber () + SequenceNumber32 (p->GetSize ()));
  // If there is any piggybacked data, process it
  if (p->GetSize ())
    {
      ReceivedData (p, sctpHeader);
    }
  // Return if FIN is out of sequence, otherwise move to SCTP_CLOSE_WAIT state by DoPeerClose
  if (!m_rxBuffer.Finished ())
    {
      return;
    }

  // Simultaneous close: Application invoked Close() when we are processing this FIN packet
  if (m_state == SCTP_FIN_WAIT_1)
    {
      NS_LOG_INFO ("SCTP_FIN_WAIT_1 -> SCTP_CLOSING");
      m_state = SCTP_CLOSING;
      return;
    }

  DoPeerClose (); // Change state, respond with ACK
}

/** Received a in-sequence FIN. Close down this socket. */
void
SctpSocketBase::DoPeerClose (void)
{
  NS_ASSERT (m_state == SCTP_ESTABLISHED || m_state == SCTP_SYN_RCVD);

  // Move the state to SCTP_CLOSE_WAIT
  NS_LOG_INFO (SctpStateName[m_state] << " -> SCTP_CLOSE_WAIT");
  m_state = SCTP_CLOSE_WAIT;

  if (!m_closeNotified)
    {
      // The normal behaviour for an application is that, when the peer sent a in-sequence
      // FIN, the app should prepare to close. The app has two choices at this point: either
      // respond with ShutdownSend() call to declare that it has nothing more to send and
      // the socket can be closed immediately; or remember the peer's close request, wait
      // until all its existing data are pushed into the SCTP socket, then call Close()
      // explicitly.
      NS_LOG_LOGIC ("SCTP " << this << " calling NotifyNormalClose");
      NotifyNormalClose ();
      m_closeNotified = true;
    }
  if (m_shutdownSend)
    { // The application declares that it would not sent any more, close this socket
      Close ();
    }
  else
    { // Need to ack, the application will close later
      SendEmptyPacket (SctpHeader::ACK);
    }
  if (m_state == SCTP_LAST_ACK)
    {
      NS_LOG_LOGIC ("SctpSocketBase " << this << " scheduling LATO1");
      m_lastAckEvent = Simulator::Schedule (m_rtt->RetransmitTimeout (),
                                            &SctpSocketBase::LastAckTimeout, this);
    }
}

/** Kill this socket. This is a callback function configured to m_endpoint in
   SetupCallback(), invoked when the endpoint is destroyed. */
void
SctpSocketBase::Destroy (void)
{
  NS_LOG_FUNCTION (this);
  m_endPoint = 0;
  if (m_sctp != 0)
    {
      std::vector<Ptr<SctpSocketBase> >::iterator it
        = std::find (m_sctp->m_sockets.begin (), m_sctp->m_sockets.end (), this);
      if (it != m_sctp->m_sockets.end ())
        {
          m_sctp->m_sockets.erase (it);
        }
    }
  NS_LOG_LOGIC (this << " Cancelled ReTxTimeout event which was set to expire at " <<
                (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
  CancelAllTimers ();
}

/** Kill this socket. This is a callback function configured to m_endpoint in
   SetupCallback(), invoked when the endpoint is destroyed. */
void
SctpSocketBase::Destroy6 (void)
{
  NS_LOG_FUNCTION (this);
  m_endPoint6 = 0;
  if (m_sctp != 0)
    {
      std::vector<Ptr<SctpSocketBase> >::iterator it
        = std::find (m_sctp->m_sockets.begin (), m_sctp->m_sockets.end (), this);
      if (it != m_sctp->m_sockets.end ())
        {
          m_sctp->m_sockets.erase (it);
        }
    }
  NS_LOG_LOGIC (this << " Cancelled ReTxTimeout event which was set to expire at " <<
                (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
  CancelAllTimers ();
}

/** Send an empty packet with specified SCTP flags */
void
SctpSocketBase::SendEmptyPacket (uint8_t flags)
{
  NS_LOG_FUNCTION (this << (uint32_t)flags);
  Ptr<Packet> p = Create<Packet> ();
  SctpHeader header;
  SequenceNumber32 s = m_nextTxSequence;

  /*
   * Add tags for each socket option.
   * Note that currently the socket adds both IPv4 tag and IPv6 tag
   * if both options are set. Once the packet got to layer three, only
   * the corresponding tags will be read.
   */
  if (IsManualIpTos ())
    {
      SocketIpTosTag ipTosTag;
      ipTosTag.SetTos (GetIpTos ());
      p->AddPacketTag (ipTosTag);
    }

  if (IsManualIpv6Tclass ())
    {
      SocketIpv6TclassTag ipTclassTag;
      ipTclassTag.SetTclass (GetIpv6Tclass ());
      p->AddPacketTag (ipTclassTag);
    }

  if (IsManualIpTtl ())
    {
      SocketIpTtlTag ipTtlTag;
      ipTtlTag.SetTtl (GetIpTtl ());
      p->AddPacketTag (ipTtlTag);
    }

  if (IsManualIpv6HopLimit ())
    {
      SocketIpv6HopLimitTag ipHopLimitTag;
      ipHopLimitTag.SetHopLimit (GetIpv6HopLimit ());
      p->AddPacketTag (ipHopLimitTag);
    }

  if (m_endPoint == 0 && m_endPoint6 == 0)
    {
      NS_LOG_WARN ("Failed to send empty packet due to null endpoint");
      return;
    }
  if (flags & SctpHeader::FIN)
    {
      flags |= SctpHeader::ACK;
    }
  else if (m_state == SCTP_FIN_WAIT_1 || m_state == SCTP_LAST_ACK || m_state == SCTP_CLOSING)
    {
      ++s;
    }

  header.SetFlags (flags);
  header.SetSequenceNumber (s);
  header.SetAckNumber (m_rxBuffer.NextRxSequence ());
  if (m_endPoint != 0)
    {
      header.SetSourcePort (m_endPoint->GetLocalPort ());
      header.SetDestinationPort (m_endPoint->GetPeerPort ());
    }
  else
    {
      header.SetSourcePort (m_endPoint6->GetLocalPort ());
      header.SetDestinationPort (m_endPoint6->GetPeerPort ());
    }
  header.SetWindowSize (AdvertisedWindowSize ());
  AddOptions (header);
  m_rto = m_rtt->RetransmitTimeout ();
  bool hasSyn = flags & SctpHeader::SYN;
  bool hasFin = flags & SctpHeader::FIN;
  bool isAck = flags == SctpHeader::ACK;
  if (hasSyn)
    {
      if (m_cnCount == 0)
        { // No more connection retries, give up
          NS_LOG_LOGIC ("Connection failed.");
          CloseAndNotify ();
          return;
        }
      else
        { // Exponential backoff of connection time out
          int backoffCount = 0x1 << (m_cnRetries - m_cnCount);
          m_rto = m_cnTimeout * backoffCount;
          m_cnCount--;
        }
    }
  if (m_endPoint != 0)
    {
      m_sctp->SendPacket (p, header, m_endPoint->GetLocalAddress (),
                         m_endPoint->GetPeerAddress (), m_boundnetdevice);
    }
  else
    {
      m_sctp->SendPacket (p, header, m_endPoint6->GetLocalAddress (),
                         m_endPoint6->GetPeerAddress (), m_boundnetdevice);
    }
  if (flags & SctpHeader::ACK)
    { // If sending an ACK, cancel the delay ACK as well
      m_delAckEvent.Cancel ();
      m_delAckCount = 0;
    }
  if (m_retxEvent.IsExpired () && (hasSyn || hasFin) && !isAck )
    { // Retransmit SYN / SYN+ACK / FIN / FIN+ACK to guard against lost
      NS_LOG_LOGIC ("Schedule retransmission timeout at time "
                    << Simulator::Now ().GetSeconds () << " to expire at time "
                    << (Simulator::Now () + m_rto.Get ()).GetSeconds ());
      m_retxEvent = Simulator::Schedule (m_rto, &SctpSocketBase::SendEmptyPacket, this, flags);
    }
}

/** This function closes the endpoint completely. Called upon RST_TX action. */
void
SctpSocketBase::SendRST (void)
{
  NS_LOG_FUNCTION (this);
  SendEmptyPacket (SctpHeader::RST);
  NotifyErrorClose ();
  DeallocateEndPoint ();
}

/** Deallocate the end point and cancel all the timers */
void
SctpSocketBase::DeallocateEndPoint (void)
{
  if (m_endPoint != 0)
    {
      m_endPoint->SetDestroyCallback (MakeNullCallback<void> ());
      m_sctp->DeAllocate (m_endPoint);
      m_endPoint = 0;
      std::vector<Ptr<SctpSocketBase> >::iterator it
        = std::find (m_sctp->m_sockets.begin (), m_sctp->m_sockets.end (), this);
      if (it != m_sctp->m_sockets.end ())
        {
          m_sctp->m_sockets.erase (it);
        }
      CancelAllTimers ();
    }
  if (m_endPoint6 != 0)
    {
      m_endPoint6->SetDestroyCallback (MakeNullCallback<void> ());
      m_sctp->DeAllocate (m_endPoint6);
      m_endPoint6 = 0;
      std::vector<Ptr<SctpSocketBase> >::iterator it
        = std::find (m_sctp->m_sockets.begin (), m_sctp->m_sockets.end (), this);
      if (it != m_sctp->m_sockets.end ())
        {
          m_sctp->m_sockets.erase (it);
        }
      CancelAllTimers ();
    }
}

/** Configure the endpoint to a local address. Called by Connect() if Bind() didn't specify one. */
int
SctpSocketBase::SetupEndpoint ()
{
  NS_LOG_FUNCTION (this);
  Ptr<Ipv4> ipv4 = m_node->GetObject<Ipv4> ();
  NS_ASSERT (ipv4 != 0);
  if (ipv4->GetRoutingProtocol () == 0)
    {
      NS_FATAL_ERROR ("No Ipv4RoutingProtocol in the node");
    }
  // Create a dummy packet, then ask the routing function for the best output
  // interface's address
  Ipv4Header header;
  header.SetDestination (m_endPoint->GetPeerAddress ());
  Socket::SocketErrno errno_;
  Ptr<Ipv4Route> route;
  Ptr<NetDevice> oif = m_boundnetdevice;
  route = ipv4->GetRoutingProtocol ()->RouteOutput (Ptr<Packet> (), header, oif, errno_);
  if (route == 0)
    {
      NS_LOG_LOGIC ("Route to " << m_endPoint->GetPeerAddress () << " does not exist");
      NS_LOG_ERROR (errno_);
      m_errno = errno_;
      return -1;
    }
  NS_LOG_LOGIC ("Route exists");
  m_endPoint->SetLocalAddress (route->GetSource ());
  return 0;
}

int
SctpSocketBase::SetupEndpoint6 ()
{
  NS_LOG_FUNCTION (this);
  Ptr<Ipv6L3Protocol> ipv6 = m_node->GetObject<Ipv6L3Protocol> ();
  NS_ASSERT (ipv6 != 0);
  if (ipv6->GetRoutingProtocol () == 0)
    {
      NS_FATAL_ERROR ("No Ipv6RoutingProtocol in the node");
    }
  // Create a dummy packet, then ask the routing function for the best output
  // interface's address
  Ipv6Header header;
  header.SetDestinationAddress (m_endPoint6->GetPeerAddress ());
  Socket::SocketErrno errno_;
  Ptr<Ipv6Route> route;
  Ptr<NetDevice> oif = m_boundnetdevice;
  route = ipv6->GetRoutingProtocol ()->RouteOutput (Ptr<Packet> (), header, oif, errno_);
  if (route == 0)
    {
      NS_LOG_LOGIC ("Route to " << m_endPoint6->GetPeerAddress () << " does not exist");
      NS_LOG_ERROR (errno_);
      m_errno = errno_;
      return -1;
    }
  NS_LOG_LOGIC ("Route exists");
  m_endPoint6->SetLocalAddress (route->GetSource ());
  return 0;
}

/** This function is called only if a SYN received in SCTP_LISTEN state. After
   SctpSocketBase cloned, allocate a new end point to handle the incoming
   connection and send a SYN+ACK to complete the handshake. */
void
SctpSocketBase::CompleteFork (Ptr<Packet> p, const SctpHeader& h,
                             const Address& fromAddress, const Address& toAddress)
{
  // Get port and address from peer (connecting host)
  if (InetSocketAddress::IsMatchingType (toAddress))
    {
      m_endPoint = m_sctp->Allocate (InetSocketAddress::ConvertFrom (toAddress).GetIpv4 (),
                                    InetSocketAddress::ConvertFrom (toAddress).GetPort (),
                                    InetSocketAddress::ConvertFrom (fromAddress).GetIpv4 (),
                                    InetSocketAddress::ConvertFrom (fromAddress).GetPort ());
      m_endPoint6 = 0;
    }
  else if (Inet6SocketAddress::IsMatchingType (toAddress))
    {
      m_endPoint6 = m_sctp->Allocate6 (Inet6SocketAddress::ConvertFrom (toAddress).GetIpv6 (),
                                      Inet6SocketAddress::ConvertFrom (toAddress).GetPort (),
                                      Inet6SocketAddress::ConvertFrom (fromAddress).GetIpv6 (),
                                      Inet6SocketAddress::ConvertFrom (fromAddress).GetPort ());
      m_endPoint = 0;
    }
  m_sctp->m_sockets.push_back (this);

  // Change the cloned socket from SCTP_LISTEN state to SCTP_SYN_RCVD
  NS_LOG_INFO ("SCTP_LISTEN -> SCTP_SYN_RCVD");
  m_state = SCTP_SYN_RCVD;
  m_cnCount = m_cnRetries;
  SetupCallback ();
  // Set the sequence number and send SYN+ACK
  m_rxBuffer.SetNextRxSequence (h.GetSequenceNumber () + SequenceNumber32 (1));
  SendEmptyPacket (SctpHeader::SYN | SctpHeader::ACK);
}

void
SctpSocketBase::ConnectionSucceeded ()
{ // Wrapper to protected function NotifyConnectionSucceeded() so that it can
  // be called as a scheduled event
  NotifyConnectionSucceeded ();
  // The if-block below was moved from ProcessSynSent() to here because we need
  // to invoke the NotifySend() only after NotifyConnectionSucceeded() to
  // reflect the behaviour in the real world.
  if (GetTxAvailable () > 0)
    {
      NotifySend (GetTxAvailable ());
    }
}

/** Extract at most maxSize bytes from the TxBuffer at sequence seq, add the
    SCTP header, and send to SctpL4Protocol */
uint32_t
SctpSocketBase::SendDataPacket (SequenceNumber32 seq, uint32_t maxSize, bool withAck)
{
  NS_LOG_FUNCTION (this << seq << maxSize << withAck);

  Ptr<Packet> p = m_txBuffer.CopyFromSequence (maxSize, seq);
  uint32_t sz = p->GetSize (); // Size of packet
  uint8_t flags = withAck ? SctpHeader::ACK : 0;
  uint32_t remainingData = m_txBuffer.SizeFromSequence (seq + SequenceNumber32 (sz));

  /*
   * Add tags for each socket option.
   * Note that currently the socket adds both IPv4 tag and IPv6 tag
   * if both options are set. Once the packet got to layer three, only
   * the corresponding tags will be read.
   */
  if (IsManualIpTos ())
    {
      SocketIpTosTag ipTosTag;
      ipTosTag.SetTos (GetIpTos ());
      p->AddPacketTag (ipTosTag);
    }

  if (IsManualIpv6Tclass ())
    {
      SocketIpv6TclassTag ipTclassTag;
      ipTclassTag.SetTclass (GetIpv6Tclass ());
      p->AddPacketTag (ipTclassTag);
    }

  if (IsManualIpTtl ())
    {
      SocketIpTtlTag ipTtlTag;
      ipTtlTag.SetTtl (GetIpTtl ());
      p->AddPacketTag (ipTtlTag);
    }

  if (IsManualIpv6HopLimit ())
    {
      SocketIpv6HopLimitTag ipHopLimitTag;
      ipHopLimitTag.SetHopLimit (GetIpv6HopLimit ());
      p->AddPacketTag (ipHopLimitTag);
    }

  if (m_closeOnEmpty && (remainingData == 0))
    {
      flags |= SctpHeader::FIN;
      if (m_state == SCTP_ESTABLISHED)
        { // On active close: I am the first one to send FIN
          NS_LOG_INFO ("SCTP_ESTABLISHED -> SCTP_FIN_WAIT_1");
          m_state = SCTP_FIN_WAIT_1;
        }
      else if (m_state == SCTP_CLOSE_WAIT)
        { // On passive close: Peer sent me FIN already
          NS_LOG_INFO ("SCTP_CLOSE_WAIT -> SCTP_LAST_ACK");
          m_state = SCTP_LAST_ACK;
        }
    }
  SctpHeader header;
  header.SetFlags (flags);
  header.SetSequenceNumber (seq);
  header.SetAckNumber (m_rxBuffer.NextRxSequence ());
  if (m_endPoint)
    {
      header.SetSourcePort (m_endPoint->GetLocalPort ());
      header.SetDestinationPort (m_endPoint->GetPeerPort ());
    }
  else
    {
      header.SetSourcePort (m_endPoint6->GetLocalPort ());
      header.SetDestinationPort (m_endPoint6->GetPeerPort ());
    }
  header.SetWindowSize (AdvertisedWindowSize ());
  AddOptions (header);
  if (m_retxEvent.IsExpired () )
    { // Schedule retransmit
      m_rto = m_rtt->RetransmitTimeout ();
      NS_LOG_LOGIC (this << " SendDataPacket Schedule ReTxTimeout at time " <<
                    Simulator::Now ().GetSeconds () << " to expire at time " <<
                    (Simulator::Now () + m_rto.Get ()).GetSeconds () );
      m_retxEvent = Simulator::Schedule (m_rto, &SctpSocketBase::ReTxTimeout, this);
    }
  NS_LOG_LOGIC ("Send packet via SctpL4Protocol with flags 0x" << std::hex << static_cast<uint32_t> (flags) << std::dec);
  if (m_endPoint)
    {
      m_sctp->SendPacket (p, header, m_endPoint->GetLocalAddress (),
                         m_endPoint->GetPeerAddress (), m_boundnetdevice);
    }
  else
    {
      m_sctp->SendPacket (p, header, m_endPoint6->GetLocalAddress (),
                         m_endPoint6->GetPeerAddress (), m_boundnetdevice);
    }
  m_rtt->SentSeq (seq, sz);       // notify the RTT
  // Notify the application of the data being sent unless this is a retransmit
  if (seq == m_nextTxSequence)
    {
      Simulator::ScheduleNow (&SctpSocketBase::NotifyDataSent, this, sz);
    }
  // Update highTxMark
  m_highTxMark = std::max (seq + sz, m_highTxMark.Get ());
  return sz;
}

/** Send as much pending data as possible according to the Tx window. Note that
 *  this function did not implement the PSH flag
 */
bool
SctpSocketBase::SendPendingData (bool withAck)
{
  NS_LOG_FUNCTION (this << withAck);
  if (m_txBuffer.Size () == 0)
    {
      return false;                           // Nothing to send

    }
  if (m_endPoint == 0 && m_endPoint6 == 0)
    {
      NS_LOG_INFO ("SctpSocketBase::SendPendingData: No endpoint; m_shutdownSend=" << m_shutdownSend);
      return false; // Is this the right way to handle this condition?
    }
  uint32_t nPacketsSent = 0;
  while (m_txBuffer.SizeFromSequence (m_nextTxSequence))
    {
      uint32_t w = AvailableWindow (); // Get available window size
      NS_LOG_LOGIC ("SctpSocketBase " << this << " SendPendingData" <<
                    " w " << w <<
                    " rxwin " << m_rWnd <<
                    " segsize " << m_segmentSize <<
                    " nextTxSeq " << m_nextTxSequence <<
                    " highestRxAck " << m_txBuffer.HeadSequence () <<
                    " pd->Size " << m_txBuffer.Size () <<
                    " pd->SFS " << m_txBuffer.SizeFromSequence (m_nextTxSequence));
      // Quit if send disallowed
      if (m_shutdownSend)
        {
          m_errno = ERROR_SHUTDOWN;
          return false;
        }
      // Stop sending if we need to wait for a larger Tx window (prevent silly window syndrome)
      if (w < m_segmentSize && m_txBuffer.SizeFromSequence (m_nextTxSequence) > w)
        {
          break; // No more
        }
      // Nagle's algorithm (RFC896): Hold off sending if there is unacked data
      // in the buffer and the amount of data to send is less than one segment
      if (!m_noDelay && UnAckDataCount () > 0
          && m_txBuffer.SizeFromSequence (m_nextTxSequence) < m_segmentSize)
        {
          NS_LOG_LOGIC ("Invoking Nagle's algorithm. Wait to send.");
          break;
        }
      uint32_t s = std::min (w, m_segmentSize);  // Send no more than window
      uint32_t sz = SendDataPacket (m_nextTxSequence, s, withAck);
      nPacketsSent++;                             // Count sent this loop
      m_nextTxSequence += sz;                     // Advance next tx sequence
    }
  NS_LOG_LOGIC ("SendPendingData sent " << nPacketsSent << " packets");
  return (nPacketsSent > 0);
}

uint32_t
SctpSocketBase::UnAckDataCount ()
{
  NS_LOG_FUNCTION (this);
  return m_nextTxSequence.Get () - m_txBuffer.HeadSequence ();
}

uint32_t
SctpSocketBase::BytesInFlight ()
{
  NS_LOG_FUNCTION (this);
  return m_highTxMark.Get () - m_txBuffer.HeadSequence ();
}

uint32_t
SctpSocketBase::Window ()
{
  NS_LOG_FUNCTION (this);
  return m_rWnd;
}

uint32_t
SctpSocketBase::AvailableWindow ()
{
  NS_LOG_FUNCTION_NOARGS ();
  uint32_t unack = UnAckDataCount (); // Number of outstanding bytes
  uint32_t win = Window (); // Number of bytes allowed to be outstanding
  NS_LOG_LOGIC ("UnAckCount=" << unack << ", Win=" << win);
  return (win < unack) ? 0 : (win - unack);
}

uint16_t
SctpSocketBase::AdvertisedWindowSize ()
{
  return std::min (m_rxBuffer.MaxBufferSize () - m_rxBuffer.Size (), (uint32_t)m_maxWinSize);
}

// Receipt of new packet, put into Rx buffer
void
SctpSocketBase::ReceivedData (Ptr<Packet> p, const SctpHeader& sctpHeader)
{
  NS_LOG_FUNCTION (this << sctpHeader);
  NS_LOG_LOGIC ("seq " << sctpHeader.GetSequenceNumber () <<
                " ack " << sctpHeader.GetAckNumber () <<
                " pkt size " << p->GetSize () );

  // Put into Rx buffer
  SequenceNumber32 expectedSeq = m_rxBuffer.NextRxSequence ();
  if (!m_rxBuffer.Add (p, sctpHeader))
    { // Insert failed: No data or RX buffer full
      SendEmptyPacket (SctpHeader::ACK);
      return;
    }
  // Now send a new ACK packet acknowledging all received and delivered data
  if (m_rxBuffer.Size () > m_rxBuffer.Available () || m_rxBuffer.NextRxSequence () > expectedSeq + p->GetSize ())
    { // A gap exists in the buffer, or we filled a gap: Always ACK
      SendEmptyPacket (SctpHeader::ACK);
    }
  else
    { // In-sequence packet: ACK if delayed ack count allows
      if (++m_delAckCount >= m_delAckMaxCount)
        {
          m_delAckEvent.Cancel ();
          m_delAckCount = 0;
          SendEmptyPacket (SctpHeader::ACK);
        }
      else if (m_delAckEvent.IsExpired ())
        {
          m_delAckEvent = Simulator::Schedule (m_delAckTimeout,
                                               &SctpSocketBase::DelAckTimeout, this);
          NS_LOG_LOGIC (this << " scheduled delayed ACK at " << (Simulator::Now () + Simulator::GetDelayLeft (m_delAckEvent)).GetSeconds ());
        }
    }
  // Notify app to receive if necessary
  if (expectedSeq < m_rxBuffer.NextRxSequence ())
    { // NextRxSeq advanced, we have something to send to the app
      if (!m_shutdownRecv)
        {
          NotifyDataRecv ();
        }
      // Handle exceptions
      if (m_closeNotified)
        {
          NS_LOG_WARN ("Why SCTP " << this << " got data after close notification?");
        }
      // If we received FIN before and now completed all "holes" in rx buffer,
      // invoke peer close procedure
      if (m_rxBuffer.Finished () && (sctpHeader.GetFlags () & SctpHeader::FIN) == 0)
        {
          DoPeerClose ();
        }
    }
}

/** Called by ForwardUp() to estimate RTT */
void
SctpSocketBase::EstimateRtt (const SctpHeader& sctpHeader)
{
  // Use m_rtt for the estimation. Note, RTT of duplicated acknowledgement
  // (which should be ignored) is handled by m_rtt. Once timestamp option
  // is implemented, this function would be more elaborated.
  Time nextRtt =  m_rtt->AckSeq (sctpHeader.GetAckNumber () );

  //nextRtt will be zero for dup acks.  Don't want to update lastRtt in that case
  //but still needed to do list clearing that is done in AckSeq. 
  if(nextRtt != 0)
  {
    m_lastRtt = nextRtt;
    NS_LOG_FUNCTION(this << m_lastRtt);
  }
  
}

// Called by the ReceivedAck() when new ACK received and by ProcessSynRcvd()
// when the three-way handshake completed. This cancels retransmission timer
// and advances Tx window
void
SctpSocketBase::NewAck (SequenceNumber32 const& ack)
{
  NS_LOG_FUNCTION (this << ack);

  if (m_state != SCTP_SYN_RCVD)
    { // Set RTO unless the ACK is received in SCTP_SYN_RCVD state
      NS_LOG_LOGIC (this << " Cancelled ReTxTimeout event which was set to expire at " <<
                    (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel ();
      // On recieving a "New" ack we restart retransmission timer .. RFC 2988
      m_rto = m_rtt->RetransmitTimeout ();
      NS_LOG_LOGIC (this << " Schedule ReTxTimeout at time " <<
                    Simulator::Now ().GetSeconds () << " to expire at time " <<
                    (Simulator::Now () + m_rto.Get ()).GetSeconds ());
      m_retxEvent = Simulator::Schedule (m_rto, &SctpSocketBase::ReTxTimeout, this);
    }
  if (m_rWnd.Get () == 0 && m_persistEvent.IsExpired ())
    { // Zero window: Enter persist state to send 1 byte to probe
      NS_LOG_LOGIC (this << "Enter zerowindow persist state");
      NS_LOG_LOGIC (this << "Cancelled ReTxTimeout event which was set to expire at " <<
                    (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel ();
      NS_LOG_LOGIC ("Schedule persist timeout at time " <<
                    Simulator::Now ().GetSeconds () << " to expire at time " <<
                    (Simulator::Now () + m_persistTimeout).GetSeconds ());
      m_persistEvent = Simulator::Schedule (m_persistTimeout, &SctpSocketBase::PersistTimeout, this);
      NS_ASSERT (m_persistTimeout == Simulator::GetDelayLeft (m_persistEvent));
    }
  // Note the highest ACK and tell app to send more
  NS_LOG_LOGIC ("SCTP " << this << " NewAck " << ack <<
                " numberAck " << (ack - m_txBuffer.HeadSequence ())); // Number bytes ack'ed
  m_txBuffer.DiscardUpTo (ack);
  if (GetTxAvailable () > 0)
    {
      NotifySend (GetTxAvailable ());
    }
  if (ack > m_nextTxSequence)
    {
      m_nextTxSequence = ack; // If advanced
    }
  if (m_txBuffer.Size () == 0 && m_state != SCTP_FIN_WAIT_1 && m_state != SCTP_CLOSING)
    { // No retransmit timer if no data to retransmit
      NS_LOG_LOGIC (this << " Cancelled ReTxTimeout event which was set to expire at " <<
                    (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel ();
    }
  // Try to send more data
  SendPendingData (m_connected);
}

// Retransmit timeout
void
SctpSocketBase::ReTxTimeout ()
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC (this << " ReTxTimeout Expired at time " << Simulator::Now ().GetSeconds ());
  // If erroneous timeout in closed/timed-wait state, just return
  if (m_state == SCTP_CLOSED || m_state == SCTP_TIME_WAIT)
    {
      return;
    }
  // If all data are received (non-closing socket and nothing to send), just return
  if (m_state <= SCTP_ESTABLISHED && m_txBuffer.HeadSequence () >= m_highTxMark)
    {
      return;
    }

  Retransmit ();
}

void
SctpSocketBase::DelAckTimeout (void)
{
  m_delAckCount = 0;
  SendEmptyPacket (SctpHeader::ACK);
}

void
SctpSocketBase::LastAckTimeout (void)
{
  NS_LOG_FUNCTION (this);

  m_lastAckEvent.Cancel ();
  if (m_state == SCTP_LAST_ACK)
    {
      CloseAndNotify ();
    }
  if (!m_closeNotified)
    {
      m_closeNotified = true;
    }
}

// Send 1-byte data to probe for the window size at the receiver when
// the local knowledge tells that the receiver has zero window size
// C.f.: RFC793 p.42, RFC1112 sec.4.2.2.17
void
SctpSocketBase::PersistTimeout ()
{
  NS_LOG_LOGIC ("PersistTimeout expired at " << Simulator::Now ().GetSeconds ());
  m_persistTimeout = std::min (Seconds (60), Time (2 * m_persistTimeout)); // max persist timeout = 60s
  Ptr<Packet> p = m_txBuffer.CopyFromSequence (1, m_nextTxSequence);
  SctpHeader sctpHeader;
  sctpHeader.SetSequenceNumber (m_nextTxSequence);
  sctpHeader.SetAckNumber (m_rxBuffer.NextRxSequence ());
  sctpHeader.SetWindowSize (AdvertisedWindowSize ());
  if (m_endPoint != 0)
    {
      sctpHeader.SetSourcePort (m_endPoint->GetLocalPort ());
      sctpHeader.SetDestinationPort (m_endPoint->GetPeerPort ());
    }
  else
    {
      sctpHeader.SetSourcePort (m_endPoint6->GetLocalPort ());
      sctpHeader.SetDestinationPort (m_endPoint6->GetPeerPort ());
    }
  AddOptions (sctpHeader);

  if (m_endPoint != 0)
    {
      m_sctp->SendPacket (p, sctpHeader, m_endPoint->GetLocalAddress (),
                         m_endPoint->GetPeerAddress (), m_boundnetdevice);
    }
  else
    {
      m_sctp->SendPacket (p, sctpHeader, m_endPoint6->GetLocalAddress (),
                         m_endPoint6->GetPeerAddress (), m_boundnetdevice);
    }
  NS_LOG_LOGIC ("Schedule persist timeout at time "
                << Simulator::Now ().GetSeconds () << " to expire at time "
                << (Simulator::Now () + m_persistTimeout).GetSeconds ());
  m_persistEvent = Simulator::Schedule (m_persistTimeout, &SctpSocketBase::PersistTimeout, this);
}

void
SctpSocketBase::Retransmit ()
{
  m_nextTxSequence = m_txBuffer.HeadSequence (); // Start from highest Ack
  m_rtt->IncreaseMultiplier (); // Double the timeout value for next retx timer
  m_dupAckCount = 0;
  DoRetransmit (); // Retransmit the packet
}

void
SctpSocketBase::DoRetransmit ()
{
  NS_LOG_FUNCTION (this);
  // Retransmit SYN packet
  if (m_state == SCTP_SYN_SENT)
    {
      if (m_cnCount > 0)
        {
          SendEmptyPacket (SctpHeader::SYN);
        }
      else
        {
          NotifyConnectionFailed ();
        }
      return;
    }
  // Retransmit non-data packet: Only if in SCTP_FIN_WAIT_1 or SCTP_CLOSING state
  if (m_txBuffer.Size () == 0)
    {
      if (m_state == SCTP_FIN_WAIT_1 || m_state == SCTP_CLOSING)
        { // Must have lost FIN, re-send
          SendEmptyPacket (SctpHeader::FIN);
        }
      return;
    }
  // Retransmit a data packet: Call SendDataPacket
  NS_LOG_LOGIC ("SctpSocketBase " << this << " retxing seq " << m_txBuffer.HeadSequence ());
  uint32_t sz = SendDataPacket (m_txBuffer.HeadSequence (), m_segmentSize, true);
  // In case of RTO, advance m_nextTxSequence
  m_nextTxSequence = std::max (m_nextTxSequence.Get (), m_txBuffer.HeadSequence () + sz);

}

void
SctpSocketBase::CancelAllTimers ()
{
  m_retxEvent.Cancel ();
  m_persistEvent.Cancel ();
  m_delAckEvent.Cancel ();
  m_lastAckEvent.Cancel ();
  m_timewaitEvent.Cancel ();
}

/** Move SCTP to Time_Wait state and schedule a transition to Closed state */
void
SctpSocketBase::TimeWait ()
{
  NS_LOG_INFO (SctpStateName[m_state] << " -> SCTP_TIME_WAIT");
  m_state = SCTP_TIME_WAIT;
  CancelAllTimers ();
  // Move from SCTP_TIME_WAIT to SCTP_CLOSED after 2*MSL. Max segment lifetime is 2 min
  // according to RFC793, p.28
  m_timewaitEvent = Simulator::Schedule (Seconds (2 * m_msl),
                                         &SctpSocketBase::CloseAndNotify, this);
}

/** Below are the attribute get/set functions */

void
SctpSocketBase::SetSndBufSize (uint32_t size)
{
  m_txBuffer.SetMaxBufferSize (size);
}

uint32_t
SctpSocketBase::GetSndBufSize (void) const
{
  return m_txBuffer.MaxBufferSize ();
}

void
SctpSocketBase::SetRcvBufSize (uint32_t size)
{
  m_rxBuffer.SetMaxBufferSize (size);
}

uint32_t
SctpSocketBase::GetRcvBufSize (void) const
{
  return m_rxBuffer.MaxBufferSize ();
}

void
SctpSocketBase::SetSegSize (uint32_t size)
{
  m_segmentSize = size;
  NS_ABORT_MSG_UNLESS (m_state == SCTP_CLOSED, "Cannot change segment size dynamically.");
}

uint32_t
SctpSocketBase::GetSegSize (void) const
{
  return m_segmentSize;
}

void
SctpSocketBase::SetConnTimeout (Time timeout)
{
  m_cnTimeout = timeout;
}

Time
SctpSocketBase::GetConnTimeout (void) const
{
  return m_cnTimeout;
}

void
SctpSocketBase::SetConnCount (uint32_t count)
{
  m_cnRetries = count;
}

uint32_t
SctpSocketBase::GetConnCount (void) const
{
  return m_cnRetries;
}

void
SctpSocketBase::SetDelAckTimeout (Time timeout)
{
  m_delAckTimeout = timeout;
}

Time
SctpSocketBase::GetDelAckTimeout (void) const
{
  return m_delAckTimeout;
}

void
SctpSocketBase::SetDelAckMaxCount (uint32_t count)
{
  m_delAckMaxCount = count;
}

uint32_t
SctpSocketBase::GetDelAckMaxCount (void) const
{
  return m_delAckMaxCount;
}

void
SctpSocketBase::SetSctpNoDelay (bool noDelay)
{
  m_noDelay = noDelay;
}

bool
SctpSocketBase::GetSctpNoDelay (void) const
{
  return m_noDelay;
}

void
SctpSocketBase::SetPersistTimeout (Time timeout)
{
  m_persistTimeout = timeout;
}

Time
SctpSocketBase::GetPersistTimeout (void) const
{
  return m_persistTimeout;
}

bool
SctpSocketBase::SetAllowBroadcast (bool allowBroadcast)
{
  // Broadcast is not implemented. Return true only if allowBroadcast==false
  return (!allowBroadcast);
}

bool
SctpSocketBase::GetAllowBroadcast (void) const
{
  return false;
}

/** Placeholder function for future extension that reads more from the SCTP header */
void
SctpSocketBase::ReadOptions (const SctpHeader&)
{
}

/** Placeholder function for future extension that changes the SCTP header */
void
SctpSocketBase::AddOptions (SctpHeader&)
{
}

} // namespace ns3
