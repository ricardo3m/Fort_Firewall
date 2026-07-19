#ifndef CONFMANAGERBASE_H
#define CONFMANAGERBASE_H

#include <QList>
#include <QObject>

#include <sqlite/sqliteutilbase.h>

class ConfManagerBase : public QObject, public SqliteUtilBase
{
    Q_OBJECT

public:
    explicit ConfManagerBase(QObject *parent = nullptr);

    SqliteDb *sqliteDb() const override;

    // Collect the sorted-unique union of all NET_LUIDs referenced by apps and rules.
    QList<quint64> collectIfaceLuids() const;
};

#endif // CONFMANAGERBASE_H
