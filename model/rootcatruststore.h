#ifndef ROOTCATRUSTSTORE_H
#define ROOTCATRUSTSTORE_H

#include <QByteArray>
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>
#include <mutex>
#include <openssl/x509.h>

class RootCATrustStore {
public:
    static X509_STORE* getTrustStore();

    static void freeStore();

private:
    RootCATrustStore() = delete;
    ~RootCATrustStore() = delete;

    static X509_STORE* store;
    static std::mutex mtx;

    static X509* loadX509FromPem(const QByteArray& pem);
};

#endif // ROOTCATRUSTSTORE_H
