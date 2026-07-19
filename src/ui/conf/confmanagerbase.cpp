#include "confmanagerbase.h"

#include <sqlite/dbquery.h>
#include <sqlite/sqlitedb.h>
#include <sqlite/sqlitestmt.h>

#include <fortglobal.h>

#include "confmanager.h"

ConfManagerBase::ConfManagerBase(QObject *parent) : QObject(parent) { }

SqliteDb *ConfManagerBase::sqliteDb() const
{
    return Fort::confManager()->sqliteDb();
}

QList<quint64> ConfManagerBase::collectIfaceLuids() const
{
    QList<quint64> luids;

    const char *const sql = "SELECT DISTINCT iface_luid FROM app WHERE iface_luid != 0"
                            "  UNION"
                            "  SELECT DISTINCT iface_luid FROM rule WHERE iface_luid != 0;";

    SqliteStmt stmt;
    if (!DbQuery(sqliteDb()).sql(sql).prepare(stmt))
        return luids;

    while (stmt.step() == SqliteStmt::StepRow) {
        luids.append(quint64(stmt.columnInt64(0)));
    }

    return luids;
}
