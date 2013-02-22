/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#ifndef SCTP_NEWRENO_H
#define SCTP_NEWRENO_H

#include "sctp-socket-base.h"

namespace ns3 {

/**
 * \ingroup socket
 * \ingroup sctp
 *
 * \brief An implementation of a stream socket using SCTP.
 *
 * This class contains the NewReno implementation of SCTP, as of RFC2582.
 */
class SctpNewReno : public SctpSocketBase
{
public:
  static TypeId GetTypeId (void);
  /**
   * Create an unbound sctp socket.
   */
  SctpNewReno (void);
  SctpNewReno (const SctpNewReno& sock);
  virtual ~SctpNewReno (void);

  // From SctpSocketBase
  virtual int Connect (const Address &address);
  virtual int Listen (void);

protected:
  virtual uint32_t Window (void); // Return the max possible number of unacked bytes
  virtual Ptr<SctpSocketBase> Fork (void); // Call CopyObject<SctpNewReno> to clone me
  virtual void NewAck (SequenceNumber32 const& seq); // Inc cwnd and call NewAck() of parent
  virtual void DupAck (const SctpHeader& t, uint32_t count);  // Halving cwnd and reset nextTxSequence
  virtual void Retransmit (void); // Exit fast recovery upon retransmit timeout

  // Implementing ns3::SctpSocket -- Attribute get/set
  virtual void     SetSegSize (uint32_t size);
  virtual void     SetSSThresh (uint32_t threshold);
  virtual uint32_t GetSSThresh (void) const;
  virtual void     SetInitialCwnd (uint32_t cwnd);
  virtual uint32_t GetInitialCwnd (void) const;
private:
  void InitializeCwnd (void);            // set m_cWnd when connection starts

protected:
  TracedValue<uint32_t>  m_cWnd;         //< Congestion window
  uint32_t               m_ssThresh;     //< Slow Start Threshold
  uint32_t               m_initialCWnd;  //< Initial cWnd value
  SequenceNumber32       m_recover;      //< Previous highest Tx seqnum for fast recovery
  uint32_t               m_retxThresh;   //< Fast Retransmit threshold
  bool                   m_inFastRec;    //< currently in fast recovery
  bool                   m_limitedTx;    //< perform limited transmit
};

} // namespace ns3

#endif /* SCTP_NEWRENO_H */
