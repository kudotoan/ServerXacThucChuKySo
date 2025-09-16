#include "rootcatruststore.h"
#include "databasemanager.h"
#include <openssl/pem.h>

X509_STORE* RootCATrustStore::store = nullptr;
std::mutex RootCATrustStore::mtx;

X509_STORE* RootCATrustStore::getTrustStore() {
    std::lock_guard<std::mutex> lock(mtx);

    if (store) return store;

    store = X509_STORE_new();
    if (!store) return nullptr;

    QSqlQuery query(DatabaseManager::database());
    if (!query.exec("SELECT cert_pem FROM rootCA")) {
        qCritical() << "Failed to load RootCA:" << query.lastError().text();
        return store;
    }

    while (query.next()) {
        QByteArray pem = query.value("cert_pem").toByteArray();
        X509* x509 = loadX509FromPem(pem);
        if (!x509) continue;
        if (X509_STORE_add_cert(store, x509) != 1) {
            qWarning() << "Failed to add RootCA to store";
        }

        X509_free(x509);
    }

    return store;
}

void RootCATrustStore::freeStore() {
    std::lock_guard<std::mutex> lock(mtx);
    if (store) {
        X509_STORE_free(store);
        store = nullptr;
    }
}

X509* RootCATrustStore::loadX509FromPem(const QByteArray& pem) {
    BIO* bio = BIO_new_mem_buf(pem.constData(), pem.size());
    if (!bio) return nullptr;

    X509* x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return x509;
}
