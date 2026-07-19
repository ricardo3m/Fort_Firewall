#include "netchangemonitor.h"

#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

namespace {

// Debounce interval: network changes often arrive in bursts (interface down,
// address removed, address added, ...). Coalesce them into a single re-push.
constexpr int DebounceIntervalMs = 1500;

void __stdcall onIpAddressChange(PVOID callerContext, PMIB_UNICASTIPADDRESS_ROW /*row*/,
        MIB_NOTIFICATION_TYPE /*notificationType*/)
{
    auto *monitor = static_cast<NetChangeMonitor *>(callerContext);
    if (monitor == nullptr)
        return;

    // The callback runs on an arbitrary OS thread; hop back to the monitor's
    // thread before touching any Qt objects.
    QMetaObject::invokeMethod(monitor, "onRawChange", Qt::QueuedConnection);
}

void __stdcall onIpInterfaceChange(PVOID callerContext, PMIB_IPINTERFACE_ROW /*row*/,
        MIB_NOTIFICATION_TYPE /*notificationType*/)
{
    auto *monitor = static_cast<NetChangeMonitor *>(callerContext);
    if (monitor == nullptr)
        return;

    QMetaObject::invokeMethod(monitor, "onRawChange", Qt::QueuedConnection);
}

}

NetChangeMonitor::NetChangeMonitor(QObject *parent) : QObject(parent)
{
    m_debounceTimer.setSingleShot(true);
    m_debounceTimer.setInterval(DebounceIntervalMs);

    // Fire the debounced changed() signal once the burst of notifications
    // settles down.
    connect(&m_debounceTimer, &QTimer::timeout, this, &NetChangeMonitor::changed);
}

NetChangeMonitor::~NetChangeMonitor()
{
    stop();
}

void NetChangeMonitor::start()
{
    if (m_addressHandle == nullptr) {
        HANDLE handle = nullptr;
        if (NotifyUnicastIpAddressChange(AF_UNSPEC, &onIpAddressChange, this,
                    /*initialNotification=*/FALSE, &handle)
                == NO_ERROR) {
            m_addressHandle = handle;
        }
    }

    if (m_interfaceHandle == nullptr) {
        HANDLE handle = nullptr;
        if (NotifyIpInterfaceChange(AF_UNSPEC, &onIpInterfaceChange, this,
                    /*initialNotification=*/FALSE, &handle)
                == NO_ERROR) {
            m_interfaceHandle = handle;
        }
    }
}

void NetChangeMonitor::stop()
{
    m_debounceTimer.stop();

    if (m_addressHandle != nullptr) {
        CancelMibChangeNotify2(static_cast<HANDLE>(m_addressHandle));
        m_addressHandle = nullptr;
    }

    if (m_interfaceHandle != nullptr) {
        CancelMibChangeNotify2(static_cast<HANDLE>(m_interfaceHandle));
        m_interfaceHandle = nullptr;
    }
}

void NetChangeMonitor::onRawChange()
{
    // Restart the debounce window on every incoming notification.
    m_debounceTimer.start();
}
