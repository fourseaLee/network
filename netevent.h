#ifndef NETEVENT_H
#define NETEVENT_H
#include <basic_type.h>
#include <atomic>
class CNode;

class NetEventsInterface
{
public:
    virtual bool ProcessMessages(CNode* pnode, std::atomic<bool>& interrupt) = 0;
    virtual bool SendMessages(CNode* pnode, std::atomic<bool>& interrupt) = 0;
    virtual void InitializeNode(CNode* pnode) = 0;
    virtual void FinalizeNode(NodeId id, bool& update_connection_time) = 0;
};

#endif // NETEVENT_H
