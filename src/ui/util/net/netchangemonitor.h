#ifndef NETCHANGEMONITOR_H
#define NETCHANGEMONITOR_H

#include <QObject>
#include <QTimer>

// Watches for network interface / address changes and emits changed()
// (debounced) so the driver configuration can be re-pushed with freshly
// resolved interface IPs.
class NetChangeMonitor : public QObject
{
    Q_OBJECT

public:
    explicit NetChangeMonitor(QObject *parent = nullptr);
    ~NetChangeMonitor() override;

    void start();
    void stop();

signals:
    void changed();

public slots:
    // Invoked (via a queued call) from the OS notification callbacks.
    void onRawChange();

private:
    void *m_addressHandle = nullptr;
    void *m_interfaceHandle = nullptr;

    QTimer m_debounceTimer;
};

#endif // NETCHANGEMONITOR_H
