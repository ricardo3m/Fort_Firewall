#include "netinterfaceutil.h"

#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

#include <QScopedArrayPointer>

namespace {

bool isLinkLocalIp6(const quint8 *addr)
{
    // fe80::/10
    return addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80;
}

bool isLinkLocalIp4(quint32 ip4NetworkOrder)
{
    // 169.254.0.0/16 (APIPA); ip4NetworkOrder is in network byte order
    const quint8 *b = reinterpret_cast<const quint8 *>(&ip4NetworkOrder);
    return b[0] == 169 && b[1] == 254;
}

void fillAddresses(const IP_ADAPTER_ADDRESSES *adapter, NetInterfaceInfo &info)
{
    bool ip4LinkLocalOnly = true;
    bool ip6LinkLocalOnly = true;

    for (const IP_ADAPTER_UNICAST_ADDRESS *ua = adapter->FirstUnicastAddress; ua != nullptr;
            ua = ua->Next) {
        const SOCKADDR *sa = ua->Address.lpSockaddr;
        if (sa == nullptr)
            continue;

        if (sa->sa_family == AF_INET) {
            const auto *sin = reinterpret_cast<const sockaddr_in *>(sa);
            const quint32 ip4 = sin->sin_addr.s_addr; // network byte order

            const bool linkLocal = isLinkLocalIp4(ip4);
            if (!info.hasIp4 || (ip4LinkLocalOnly && !linkLocal)) {
                info.ip4 = ip4;
                info.hasIp4 = true;
                ip4LinkLocalOnly = linkLocal;
            }
        } else if (sa->sa_family == AF_INET6) {
            const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(sa);
            const quint8 *addr = sin6->sin6_addr.s6_addr;

            const bool linkLocal = isLinkLocalIp6(addr);
            if (!info.hasIp6 || (ip6LinkLocalOnly && !linkLocal)) {
                memcpy(info.ip6.data, addr, sizeof(info.ip6.data));
                info.hasIp6 = true;
                ip6LinkLocalOnly = linkLocal;
            }
        }
    }
}

} // namespace

QList<NetInterfaceInfo> NetInterfaceUtil::enumInterfaces()
{
    QList<NetInterfaceInfo> list;

    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_PREFIX;

    ULONG bufLen = 15 * 1024; // recommended initial size
    QScopedArrayPointer<char> buf;
    ULONG ret = ERROR_BUFFER_OVERFLOW;

    for (int attempt = 0; attempt < 3 && ret == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.reset(new char[bufLen]);
        ret = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buf.data()), &bufLen);
    }

    if (ret != NO_ERROR)
        return list;

    for (const auto *adapter = reinterpret_cast<const IP_ADAPTER_ADDRESSES *>(buf.data());
            adapter != nullptr; adapter = adapter->Next) {
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        NetInterfaceInfo info;
        info.luid = adapter->Luid.Value;
        info.name = QString::fromWCharArray(adapter->FriendlyName);
        info.description = QString::fromWCharArray(adapter->Description);

        fillAddresses(adapter, info);

        info.available = (adapter->OperStatus == IfOperStatusUp) && (info.hasIp4 || info.hasIp6);

        list.append(info);
    }

    return list;
}

NetInterfaceInfo NetInterfaceUtil::resolveLuid(quint64 luid)
{
    if (luid == 0)
        return {};

    const auto interfaces = enumInterfaces();
    for (const auto &info : interfaces) {
        if (info.luid == luid)
            return info;
    }

    return {};
}
