#ifndef BASIC_TYPE_H
#define BASIC_TYPE_H
#include <map>
typedef int64_t NodeId;
enum Network
{
    NET_UNROUTABLE = 0,
    NET_IPV4,
    NET_IPV6,
    NET_TOR,
    NET_INTERNAL,
    NET_MAX,
};

enum
{
    LOCAL_NONE,   // unknown
    LOCAL_IF,     // address a local interface listens on
    LOCAL_BIND,   // address explicit bound to
    LOCAL_UPNP,   // address reported by UPnP
    LOCAL_MANUAL, // address explicitly specified (-externalip=)
    LOCAL_MAX
};

/** Used to pass flags to the Bind() function */
enum BindFlags {
    BF_NONE         = 0,
    BF_EXPLICIT     = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    BF_WHITELIST    = (1U << 2),
};

typedef std::map<std::string, uint64_t> mapMsgCmdSize; //command, total bytes

struct CombinerAll
{
    typedef bool result_type;

    template<typename I>
    bool operator()(I first, I last) const
    {
        while (first != last) {
            if (!(*first)) return false;
            ++first;
        }
        return true;
    }
};


struct LocalServiceInfo {
    int nScore;
    int nPort;
};

#endif // BASIC_TYPE_H
