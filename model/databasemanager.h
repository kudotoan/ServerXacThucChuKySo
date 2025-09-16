#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H
#include <QString>
#include <QSqlDatabase>
class DatabaseManager
{
public:
    static bool connect(const QString &host = "localhost",
                        const QString &dbName = "CSRUpload",
                        const QString &user = "kudotoan",
                        const QString &password = "191199",
                        int port = 3306);

    static void disconnect();

    static QSqlDatabase database();

private:
    static inline QSqlDatabase m_db;
};

#endif // DATABASEMANAGER_H
