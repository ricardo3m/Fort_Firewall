#ifndef NETINTERFACEUTIL_H
#define NETINTERFACEUTIL_H

#include <QList>
#include <QString>

#include <common/common_types.h>

struct NetInterfaceInfo
{
    bool available = false; // interface is up and has a usable IP address
    bool hasIp4 = false;
    bool hasIp6 = false;
    quint64 luid = 0; // NET_LUID.Value
    quint32 ip4 = 0; // local IPv4 in network byte order (as in sockaddr)
    ip6_addr_t ip6 = {}; // local IPv6 bytes (as in sockaddr)
    QString name; // friendly name
    QString description;

    bool isNull() const { return luid == 0; }
};

class NetInterfaceUtil
{
public:
    // Enumerate all network interfaces (up or down) with their current addresses.
    static QList<NetInterfaceInfo> enumInterfaces();

    // Resolve a single interface by its NET_LUID value to the current IP addresses.
    // Returns an entry with available=false if the interface is missing or has no IP.
    static NetInterfaceInfo resolveLuid(quint64 luid);
};

#endif // NETINTERFACEUTIL_H
