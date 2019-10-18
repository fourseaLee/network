#ifndef NODE_H
#define NODE_H

#include "addrman.h"
#include "compat.h"
#include "network_macro.h"
#include "netaddress.h"
#include "protocol.h"
#include "basic_type.h"

#include <atomic>
#include <deque>
#include <stdint.h>
#include <thread>
#include <memory>
#include <condition_variable>
#include <list>

#ifndef WIN32
#include <arpa/inet.h>
#endif

class CConnman;
class CNetMessage;

class CNodeStats
{
public:
    NodeId nodeid;
    ServiceFlags nServices;

    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nTimeConnected;
    int64_t nTimeOffset;
    std::string addrName;

    bool fInbound;

    uint64_t nSendBytes;
    mapMsgCmdSize mapSendBytesPerMsgCmd;
    uint64_t nRecvBytes;
    mapMsgCmdSize mapRecvBytesPerMsgCmd;

    // Our address, as reported by the peer
    std::string addrLocal;
    // Address of this peer
    CAddress addr;
    // Bind address of our side of the connection
    CAddress addrBind;
};

class CNode
{
    friend class CConnman;
public:
    // socket
    std::atomic<ServiceFlags> nServices;
    SOCKET hSocket;
    size_t nSendSize; // total size of all vSendMsg entries
    size_t nSendOffset; // offset inside the first vSendMsg already sent
    uint64_t nSendBytes;
    std::deque<std::vector<unsigned char>> vSendMsg;
    /*CCriticalSection cs_vSend;
    CCriticalSection cs_hSocket;
    CCriticalSection cs_vRecv;

    CCriticalSection cs_vProcessMsg;*/
    std::list<CNetMessage> vProcessMsg;
    size_t nProcessQueueSize;

    //CCriticalSection cs_sendProcessing;

    std::deque<CInv> vRecvGetData;
    uint64_t nRecvBytes;
    std::atomic<int> nRecvVersion;

    std::atomic<int64_t> nLastSend;
    std::atomic<int64_t> nLastRecv;
    const int64_t nTimeConnected;
    std::atomic<int64_t> nTimeOffset;
    // Address of this peer
    const CAddress addr;
    // Bind address of our side of the connection
    const CAddress addrBind;

    bool fClient;
    const bool fInbound;
    std::atomic_bool fSuccessfullyConnected;
    std::atomic_bool fDisconnect;

    bool fSentAddr;
    //CSemaphoreGrant grantOutbound;

    std::atomic<int> nRefCount;

    const uint64_t nKeyedNetGroup;
    std::atomic_bool fPauseRecv;
    std::atomic_bool fPauseSend;
protected:

    mapMsgCmdSize mapSendBytesPerMsgCmd;
    mapMsgCmdSize mapRecvBytesPerMsgCmd;

public:
    //uint256 hashContinue;
    std::atomic<int> nStartingHeight;

    // flood relay
    std::vector<CAddress> vAddrToSend;
    //CRollingBloomFilter addrKnown;
    bool fGetAddr;
    //std::set<uint256> setKnown;
    int64_t nNextAddrSend;
    int64_t nNextLocalAddrSend;

    // inventory based relay
    //CRollingBloomFilter filterInventoryKnown;
    // Set of transaction ids we still have to announce.
    // They are sorted by the mempool before relay, so the order is not important.
    //std::set<uint256> setInventoryTxToSend;
    // List of block ids we still have announce.
    // There is no final sorting before sending, as they are always sent immediately
    // and in the order requested.
    //std::vector<uint256> vInventoryBlockToSend;
    //CCriticalSection cs_inventory;
    //std::set<uint256> setAskFor;
    std::multimap<int64_t, CInv> mapAskFor;
    int64_t nNextInvSend;
    // Used for headers announcements - unfiltered blocks to relay
    // Also protected by cs_inventory
    //std::vector<uint256> vBlockHashesToAnnounce;
    // Used for BIP35 mempool sending, also protected by cs_inventory
    bool fSendMempool;

    // Last time a "MEMPOOL" request was serviced.
    std::atomic<int64_t> timeLastMempoolReq;

    // Block and TXN accept times
    std::atomic<int64_t> nLastBlockTime;
    std::atomic<int64_t> nLastTXTime;

    // Ping time measurement:
    // The pong reply we're expecting, or 0 if no pong expected.
    std::atomic<uint64_t> nPingNonceSent;
    // Time (in usec) the last ping was sent, or 0 if no ping was ever sent.
    std::atomic<int64_t> nPingUsecStart;
    // Last measured round-trip time.
    std::atomic<int64_t> nPingUsecTime;
    // Best measured round-trip time.
    std::atomic<int64_t> nMinPingUsecTime;
    // Whether a ping is requested.
    std::atomic<bool> fPingQueued;
    // Minimum fee rate with which to filter inv's to this node
    //CAmount minFeeFilter;
    //CCriticalSection cs_feeFilter;
    //CAmount lastSentFeeFilter;
    int64_t nextSendTimeFeeFilter;

    CNode(NodeId id, ServiceFlags nLocalServicesIn, SOCKET hSocketIn, const CAddress &addrIn, uint64_t nKeyedNetGroupIn, uint64_t nLocalHostNonceIn, const CAddress &addrBindIn, const std::string &addrNameIn = "", bool fInboundIn = false);
    ~CNode();
    CNode(const CNode&) = delete;
    CNode& operator=(const CNode&) = delete;

private:
    const NodeId id;
    const uint64_t nLocalHostNonce;
    // Services offered to this peer
    const ServiceFlags nLocalServices;

    //std::list<CNetMessage> vRecvMsg;  // Used only by SocketHandler thread

    //mutable CCriticalSection cs_addrName;
    std::string addrName;

    // Our address, as reported by the peer
    CService addrLocal;
    //mutable CCriticalSection cs_addrLocal;
public:

    NodeId GetId() const
    {
        return id;
    }

    uint64_t GetLocalNonce() const
    {
        return nLocalHostNonce;
    }

    int GetRefCount() const
    {
        assert(nRefCount >= 0);
        return nRefCount;
    }

    virtual bool ReceiveMsgBytes(const char *pch, unsigned int nBytes, bool& complete);


    CService GetAddrLocal() const;
    //! May not be called more than once
    void SetAddrLocal(const CService& addrLocalIn);

    CNode* AddRef()
    {
        nRefCount++;
        return this;
    }

    void Release()
    {
        nRefCount--;
    }

    void AskFor(const CInv& inv);

    void CloseSocketDisconnect();

    void copyStats(CNodeStats &stats);

    ServiceFlags GetLocalServices() const
    {
        return nLocalServices;
    }

    std::string GetAddrName() const;
    //! Sets the addrName only if it was not previously set
    void MaybeSetAddrName(const std::string& addrNameIn);
};


#endif // NODE_H
