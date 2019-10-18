// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H
#include "network_macro.h"
#include "basic_type.h"
#include <stdint.h>
#include "protocol.h"

class CService;
class CNetAddr;
class CAddress;

//void Discover(boost::thread_group& threadGroup);

struct NodeEvictionCandidate
{
    NodeId id;
    int64_t nTimeConnected;
    int64_t nMinPingUsecTime;
    int64_t nLastBLOCKTime;
    int64_t nLastTXTime;
    bool fRelevantServices;

    CAddress addr;
    uint64_t nKeyedNetGroup;
};

bool AddLocal(const CService& addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr& addr, int nScore = LOCAL_NONE);
bool RemoveLocal(const CService& addr);

bool IsLocal(const CService& addr);
bool GetLocal(CService &addr, const CNetAddr *paddrPeer = nullptr);

/** Return a timestamp in the future (in microseconds) for exponentially distributed events. */
int64_t PoissonNextSend(int64_t nNow, int average_interval_seconds);

#endif // BITCOIN_NET_H
