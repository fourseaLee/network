#ifndef NETCONNMAN_H
#define NETCONNMAN_H
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

class NetEventsInterface;
class CNode;
class CSerializedNetMsg;
class CNodeStats;

struct AddedNodeInfo
{
    std::string strAddedNode;
    CService resolvedAddress;
    bool fConnected;
    bool fInbound;
};

class CConnman
{
public:

    enum NumConnections
    {
        CONNECTIONS_NONE = 0,
        CONNECTIONS_IN = (1U << 0),
        CONNECTIONS_OUT = (1U << 1),
        CONNECTIONS_ALL = (CONNECTIONS_IN | CONNECTIONS_OUT),
    };

    struct Options
    {
        ServiceFlags nLocalServices = NODE_NONE;
        int nMaxConnections = 0;
        int nMaxOutbound = 0;
        int nMaxAddnode = 0;
        int nMaxFeeler = 0;
        unsigned int nSendBufferMaxSize = 0;
        unsigned int nReceiveFloodSize = 0;
        uint64_t nMaxOutboundTimeframe = 0;
        uint64_t nMaxOutboundLimit = 0;

        bool m_use_addrman_outgoing = true;
        std::vector<std::string> m_specified_outgoing;
        std::vector<std::string> m_added_nodes;
    };

    void Init(const Options& connOptions)
    {
        nLocalServices = connOptions.nLocalServices;
        nMaxConnections = connOptions.nMaxConnections;
        nMaxOutbound = std::min(connOptions.nMaxOutbound, connOptions.nMaxConnections);
        nMaxAddnode = connOptions.nMaxAddnode;
        nMaxFeeler = connOptions.nMaxFeeler;
        nSendBufferMaxSize = connOptions.nSendBufferMaxSize;
        nReceiveFloodSize = connOptions.nReceiveFloodSize;
//        {
//            LOCK(cs_totalBytesSent);
//            nMaxOutboundTimeframe = connOptions.nMaxOutboundTimeframe;
//            nMaxOutboundLimit = connOptions.nMaxOutboundLimit;
//        }

//        {
//            LOCK(cs_vAddedNodes);
//            vAddedNodes = connOptions.m_added_nodes;
//        }
    }

    CConnman(uint64_t seed0, uint64_t seed1);
    virtual ~CConnman();
    virtual bool Start(const Options& options);
    virtual void Stop();
    virtual void Interrupt();
    bool GetNetworkActive() const { return fNetworkActive; }
    void SetNetworkActive(bool active);
    //void OpenNetworkConnection(const CAddress& addrConnect, bool fCountFailure, CSemaphoreGrant *grantOutbound = nullptr, const char *strDest = nullptr, bool fOneShot = false, bool fFeeler = false, bool manual_connection = false);
    bool CheckIncomingNonce(uint64_t nonce);

    bool ForNode(NodeId id, std::function<bool(CNode* pnode)> func);

    void PushMessage(CNode* pnode, CSerializedNetMsg&& msg);

    // Addrman functions
    size_t GetAddressCount() const;
    void SetServices(const CService &addr, ServiceFlags nServices);
    void MarkAddressGood(const CAddress& addr);
    void AddNewAddresses(const std::vector<CAddress>& vAddr, const CAddress& addrFrom, int64_t nTimePenalty = 0);
    std::vector<CAddress> GetAddresses();

    // This allows temporarily exceeding nMaxOutbound, with the goal of finding
    // a peer that is better than all our current peers.
    void SetTryNewOutboundPeer(bool flag);
    bool GetTryNewOutboundPeer();

    // Return the number of outbound peers we have in excess of our target (eg,
    // if we previously called SetTryNewOutboundPeer(true), and have since set
    // to false, we may have extra peers that we wish to disconnect). This may
    // return a value less than (num_outbound_connections - num_outbound_slots)
    // in cases where some outbound connections are not yet fully connected, or
    // not yet fully disconnected.
    int GetExtraOutboundCount();

    bool AddNode(const std::string& node);
    bool RemoveAddedNode(const std::string& node);
    std::vector<AddedNodeInfo> GetAddedNodeInfo();

    size_t GetNodeCount(NumConnections num);
    void GetNodeStats(std::vector<CNodeStats>& vstats);
    bool DisconnectNode(const std::string& node);
    bool DisconnectNode(NodeId id);

    ServiceFlags GetLocalServices() const;

    //!set the max outbound target in bytes
    void SetMaxOutboundTarget(uint64_t limit);
    uint64_t GetMaxOutboundTarget();

    //!set the timeframe for the max outbound target
    void SetMaxOutboundTimeframe(uint64_t timeframe);
    uint64_t GetMaxOutboundTimeframe();

    //!check if the outbound target is reached
    // if param historicalBlockServingLimit is set true, the function will
    // response true if the limit for serving historical blocks has been reached
    bool OutboundTargetReached(bool historicalBlockServingLimit);

    //!response the bytes left in the current max outbound cycle
    // in case of no limit, it will always response 0
    uint64_t GetOutboundTargetBytesLeft();

    //!response the time in second left in the current max outbound cycle
    // in case of no limit, it will always response 0
    uint64_t GetMaxOutboundTimeLeftInCycle();

    /** Get a unique deterministic randomizer. */
   // CSipHasher GetDeterministicRandomizer(uint64_t id) const;

    unsigned int GetReceiveFloodSize() const;

    virtual void WakeMessageHandler();
private:
    struct ListenSocket
    {
        SOCKET socket;
        bool whitelisted;
        ListenSocket(SOCKET socket_, bool whitelisted_) : socket(socket_), whitelisted(whitelisted_) {}
    };

    bool BindListenPort(const CService &bindAddr, std::string& strError, bool fWhitelisted = false);
    bool Bind(const CService &addr, unsigned int flags);
    bool InitBinds(const std::vector<CService>& binds, const std::vector<CService>& whiteBinds);
    virtual void ThreadOpenAddedConnections();
    virtual void ThreadOpenConnections(std::vector<std::string> connect);
    virtual void ThreadMessageHandler();
    virtual void AcceptConnection(const ListenSocket& hListenSocket);
    virtual void ThreadSocketHandler();
    virtual void ThreadDNSAddressSeed();


    virtual CNode* FindNode(const CNetAddr& ip);
    virtual CNode* FindNode(const CSubNet& subNet);
    virtual CNode* FindNode(const std::string& addrName);
    virtual CNode* FindNode(const CService& addr);

    virtual bool AttemptToEvictConnection();
    virtual CNode* ConnectNode(CAddress addrConnect, const char *pszDest, bool fCountFailure);

    virtual void DeleteNode(CNode* pnode);

    NodeId GetNewNodeId();

    size_t SocketSendData(CNode *pnode) const;

    // Network stats
    void RecordBytesRecv(uint64_t bytes);
    void RecordBytesSent(uint64_t bytes);

    // Whether the node should be passed out in ForEach* callbacks
    static bool NodeFullyConnected(const CNode* pnode);

    unsigned int nSendBufferMaxSize;
    unsigned int nReceiveFloodSize;

    std::vector<ListenSocket> vhListenSocket;
    std::atomic<bool> fNetworkActive;
    CAddrMan addrman;
    std::vector<CNode*> vNodes;
    std::atomic<NodeId> nLastNodeId;

    /** Services this instance offers */
    ServiceFlags nLocalServices;
    int nMaxConnections;
    int nMaxOutbound;
    int nMaxAddnode;
    int nMaxFeeler;

    /** SipHasher seeds for deterministic randomness */
    const uint64_t nSeed0, nSeed1;

    /** flag for waking the message processor. */
    bool fMsgProcWake;

    std::condition_variable condMsgProc;
    std::mutex mutexMsgProc;
    std::atomic<bool> flagInterruptMsgProc;
    /** flag for deciding to connect to an extra outbound peer,
     *  in excess of nMaxOutbound
     *  This takes the place of a feeler connection */
    std::atomic_bool m_try_another_outbound_peer;
};

bool BindListenPort(const CService &bindAddr, std::string& strError, bool fWhitelisted = false);

#endif // NETCONNMAN_H
