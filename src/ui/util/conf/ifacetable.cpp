#include "ifacetable.h"

#include <algorithm>

#include <util/net/netinterfaceutil.h>

void IfaceTable::build(const QList<quint64> &luids)
{
    m_ifaces.clear();
    m_luidToIndex.clear();

    // Sorted unique, non-zero LUIDs -> stable order across writers
    QList<quint64> sorted;
    sorted.reserve(luids.size());
    for (const quint64 luid : luids) {
        if (luid != 0 && !sorted.contains(luid)) {
            sorted.append(luid);
        }
    }
    std::sort(sorted.begin(), sorted.end());

    // Cap to the driver's maximum
    if (sorted.size() > FORT_CONF_IFACE_MAX) {
        sorted.resize(FORT_CONF_IFACE_MAX);
    }

    quint8 index = 0;
    for (const quint64 luid : sorted) {
        const NetInterfaceInfo info = NetInterfaceUtil::resolveLuid(luid);

        FORT_CONF_IFACE iface;
        memset(&iface, 0, sizeof(iface));
        iface.luid = luid;

        if (info.available) {
            if (info.hasIp4) {
                iface.ip4 = info.ip4; // network byte order
                iface.flags |= FORT_CONF_IFACE_HAS_IP4;
            }
            if (info.hasIp6) {
                iface.ip6 = info.ip6;
                iface.flags |= FORT_CONF_IFACE_HAS_IP6;
            }
        }

        m_ifaces.append(iface);
        m_luidToIndex.insert(luid, ++index); // 1-based
    }
}
