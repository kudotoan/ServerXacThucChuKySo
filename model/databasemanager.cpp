#include "databasemanager.h"
#include <QSqlError>
#include <QDebug>

bool DatabaseManager::connect(const QString &host, const QString &dbName, const QString &user, const QString &password, int port)
{
    if (QSqlDatabase::contains("XacThuc")) {
        m_db = QSqlDatabase::database("XacThuc");
        if (m_db.isOpen()) return true;
    }

    m_db = QSqlDatabase::addDatabase("QMYSQL", "XacThuc");
    m_db.setHostName(host);
    m_db.setDatabaseName(dbName);
    m_db.setUserName(user);
    m_db.setPassword(password);
    m_db.setPort(port);
    m_db.setConnectOptions("MYSQL_OPT_SSL_MODE=SSL_MODE_DISABLED");

    if (!m_db.open()) {
        qCritical() << "Cannot connect to database:" << m_db.lastError().text();
        return false;
    }

    return true;
}

void DatabaseManager::disconnect()
{
    if (m_db.isOpen()) m_db.close();
    m_db = QSqlDatabase();
    QSqlDatabase::removeDatabase("XacThuc");
}

QSqlDatabase DatabaseManager::database()
{
    return QSqlDatabase::database("XacThuc");
}
