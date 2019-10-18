// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "net.h"
#include "netaddress.h"
#include <netbase.h>
#include "addrman.h"
#include "compat.h"
#include "timedata.h"
#include "utiltime.h"
#include "tinyformat.h"
#include "protocol.h"
#include "net_args.h"
#include "node.h"
#include "net_params.h"

#include <memory>
#include <list>

#include <atomic>

#ifdef WIN32
#include <string.h>
#else
#include <fcntl.h>
#endif

#ifndef WIN32
#include <arpa/inet.h>
#endif
#include <math.h>

//extern CCriticalSection cs_mapLocalHost;
static std::map<CNetAddr, LocalServiceInfo> mapLocalHost;

//limitedmap<uint256, int64_t> mapAlreadyAskedFor(MAX_INV_SZ);


// find 'best' local address for a particular peer
bool GetLocal(CService& addr, const CNetAddr *paddrPeer)
{
    if (!g_fListen)
        return false;

    int nBestScore = -1;
    int nBestReachability = -1;
    {
        //LOCK(cs_mapLocalHost);
        for (const auto& entry : mapLocalHost)
        {
            int nScore = entry.second.nScore;
            int nReachability = entry.first.GetReachabilityFrom(paddrPeer);
            if (nReachability > nBestReachability || (nReachability == nBestReachability && nScore > nBestScore))
            {
              //  addr = CService(entry.first, entry.second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    return nBestScore >= 0;
}

//! Convert the pnSeeds6 array into usable address objects.
/*static std::vector<CAddress> convertSeed6(const std::vector<SeedSpec6> &vSeedsIn)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    std::vector<CAddress> vSeedsOut;
    vSeedsOut.reserve(vSeedsIn.size());
    for (const auto& seed_in : vSeedsIn) {
        struct in6_addr ip;
        memcpy(&ip, seed_in.addr, sizeof(ip));
        CAddress addr(CService(ip, seed_in.port), GetDesirableServiceFlags(NODE_NONE));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
    return vSeedsOut;
}*/


int GetnScore(const CService& addr)
{
    //LOCK(cs_mapLocalHost);
    if (mapLocalHost.count(addr) == LOCAL_NONE)
        return 0;
    return mapLocalHost[addr].nScore;
}

// learn a new local address
bool AddLocal(const CService& addr, int nScore)
{
    if (!addr.IsRoutable())
        return false;

    if (!g_fDiscover && nScore < LOCAL_MANUAL)
        return false;


   ////LogPrintf("AddLocal(%s,%i)\n", addr.ToString(), nScore);

    {
        //LOCK(cs_mapLocalHost);
        bool fAlready = mapLocalHost.count(addr) > 0;
        LocalServiceInfo &info = mapLocalHost[addr];
        if (!fAlready || nScore >= info.nScore) {
            info.nScore = nScore + (fAlready ? 1 : 0);
            info.nPort = addr.GetPort();
        }
    }

    return true;
}

bool AddLocal(const CNetAddr &addr, int nScore)
{
    return AddLocal(CService(addr, g_listen_port), nScore);
}

bool RemoveLocal(const CService& addr)
{
    //LOCK(cs_mapLocalHost);
   ////LogPrintf("RemoveLocal(%s)\n", addr.ToString());
    mapLocalHost.erase(addr);
    return true;
}


/** check whether a given address is potentially local */
bool IsLocal(const CService& addr)
{
    //LOCK(cs_mapLocalHost);
    return mapLocalHost.count(addr) > 0;
}


/** Get the bind address for a socket as CAddress */
static CAddress GetBindAddress(SOCKET sock)
{
    CAddress addr_bind;
    struct sockaddr_storage sockaddr_bind;
    socklen_t sockaddr_bind_len = sizeof(sockaddr_bind);
    if (sock != INVALID_SOCKET) {
        if (!getsockname(sock, (struct sockaddr*)&sockaddr_bind, &sockaddr_bind_len)) {
            addr_bind.SetSockAddr((const struct sockaddr*)&sockaddr_bind);
        } else {
            //LogPrint(BCLog::NET, "Warning: getsockname failed\n");
        }
    }
    return addr_bind;
}




