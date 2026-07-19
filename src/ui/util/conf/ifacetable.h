#ifndef IFACETABLE_H
#define IFACETABLE_H

#include <QByteArray>
#include <QHash>
#include <QList>

#include <common/fortconf.h>

// Builds a deterministic interface table for the driver configuration.
//
// The table is the sorted-unique union of all NET_LUIDs referenced by apps
// and rules. Each interface gets a stable 1-based index (0 means "none"),
// so both the app-conf writer and the rules writer produce identical
// LUID -> index mappings when given the same set of LUIDs.
class IfaceTable
{
public:
    void build(const QList<quint64> &luids);

    bool isEmpty() const { return m_ifaces.isEmpty(); }
    int count() const { return m_ifaces.size(); }

    const QList<FORT_CONF_IFACE> &ifaces() const { return m_ifaces; }

    // Returns the 1-based index for a LUID, or 0 if none/not present.
    quint8 indexOf(quint64 luid) const { return m_luidToIndex.value(luid, 0); }

private:
    QList<FORT_CONF_IFACE> m_ifaces;
    QHash<quint64, quint8> m_luidToIndex;
};

#endif // IFACETABLE_H
