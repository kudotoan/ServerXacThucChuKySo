#include "Signature.h"
#include <QFile>
#include <QDebug>
#include "RootCATrustStore.h"
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <QDebug>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>

QDataStream& operator<<(QDataStream& out, const Signature& obj) {
    // interCACer
    out << static_cast<quint32>(obj.interCACer.size());
    for (const auto &s : obj.interCACer)
        out << s;

    // tokenCer
    out << static_cast<quint32>(obj.tokenCer.size());
    for (const auto &s : obj.tokenCer)
        out << s;

    // signature
    out << static_cast<quint32>(obj.signature.size());
    for (const auto &s : obj.signature)
        out << s;

    // fileSize
    out << static_cast<quint32>(obj.fileSize.size());
    for (auto s : obj.fileSize)
        out << static_cast<quint64>(s);  // serialize as unsigned long long

    return out;
}

QDataStream& operator>>(QDataStream& in, Signature& obj) {
    quint32 size;

    // interCACer
    in >> size;
    obj.interCACer.clear();
    obj.interCACer.reserve(size);
    for (quint32 i = 0; i < size; i++) {
        QByteArray s;
        in >> s;
        obj.interCACer.push_back(s);
    }

    // tokenCer
    in >> size;
    obj.tokenCer.clear();
    obj.tokenCer.reserve(size);
    for (quint32 i = 0; i < size; i++) {
        QByteArray s;
        in >> s;
        obj.tokenCer.push_back(s);
    }

    // signature
    in >> size;
    obj.signature.clear();
    obj.signature.reserve(size);
    for (quint32 i = 0; i < size; i++) {
        QByteArray s;
        in >> s;
        obj.signature.push_back(s);
    }

    // fileSize
    in >> size;
    obj.fileSize.clear();
    obj.fileSize.reserve(size);
    for (quint32 i = 0; i < size; i++) {
        quint64 s;
        in >> s;
        obj.fileSize.push_back(static_cast<unsigned long long>(s));
    }

    return in;
}

bool Signature::saveToFile(const QString &filePath) const {
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
        qWarning() << "Không mở được file để ghi!";
        return false;
    }

    QByteArray buffer;
    QDataStream tempOut(&buffer, QIODevice::WriteOnly);
    tempOut.setVersion(QDataStream::Qt_6_5);
    tempOut << *this;

    if (file.write(buffer) != buffer.size()) {
        qWarning() << "Không ghi đủ dữ liệu!";
        file.close();
        return false;
    }

    QDataStream out(&file);
    out.setVersion(QDataStream::Qt_6_5);
    out << static_cast<quint32>(buffer.size());

    QByteArray mark("Kudotoan", 8);
    if (file.write(mark) != mark.size()) {
        qWarning() << "Không ghi đủ dấu hiệu!";
        file.close();
        return false;
    }

    file.close();
    return true;
}


bool Signature::loadLastFromFile(const QString &filePath, Signature &outSig, qint64 &outOriginalFileSize) {
    try {
        QFile fileIn(filePath);
        if (!fileIn.open(QIODevice::ReadOnly)) {
            qWarning() << "Không mở được file để đọc!";
            return false;
        }
        QByteArray header = fileIn.read(5);
        if (header != "%PDF-") {
            qWarning() << "File không phải PDF!";
            fileIn.close();
            return false;
        }

        fileIn.seek(0);

        qint64 fileSize = fileIn.size();
        const int markSize = 8;
        const int sizeField = 4;

        outOriginalFileSize = fileSize;

        if (fileSize < markSize + sizeField) {
            fileIn.close();
            return true;
        }

        if (!fileIn.seek(fileSize - markSize)) {
            qWarning() << "Không seek được tới mark!";
            fileIn.close();
            return false;
        }

        QByteArray mark = fileIn.read(markSize);
        if (mark != "Kudotoan") {
            fileIn.close();
            return true;
        }

        if (!fileIn.seek(fileSize - markSize - sizeField)) {
            qWarning() << "Không seek được tới sizeField!";
            fileIn.close();
            return false;
        }

        QDataStream in(&fileIn);
        in.setVersion(QDataStream::Qt_6_5);
        quint32 bufferSize = 0;
        in >> bufferSize;

        if (bufferSize > static_cast<quint32>(fileSize - markSize - sizeField)) {
            qWarning() << "bufferSize quá lớn, file có thể bị hỏng!";
            fileIn.close();
            return false;
        }

        qint64 dataPos = fileSize - markSize - sizeField - bufferSize;
        if (dataPos < 0) {
            qWarning() << "File hỏng hoặc size không hợp lệ!";
            fileIn.close();
            return false;
        }

        if (!fileIn.seek(dataPos)) {
            qWarning() << "Không seek được tới dataPos!";
            fileIn.close();
            return false;
        }

        QByteArray bufferIn(bufferSize, 0);
        qint64 bytesRead = fileIn.read(bufferIn.data(), bufferSize);
        if (bytesRead != bufferSize) {
            qWarning() << "Không đọc đủ dữ liệu!";
            fileIn.close();
            return false;
        }

        // Đọc outSig
        QDataStream tempIn(&bufferIn, QIODevice::ReadOnly);
        tempIn.setVersion(QDataStream::Qt_6_5);
        tempIn >> outSig;

        outOriginalFileSize = fileSize - (bufferSize + sizeField + markSize);
        fileIn.close();
        return true;
    } catch (const std::bad_alloc &e) {
        qWarning() << "Lỗi cấp phát bộ nhớ: " << e.what();
        return false;
    } catch (const std::exception &e) {
        qWarning() << "Ngoại lệ: " << e.what();
        return false;
    } catch (...) {
        qWarning() << "Ngoại lệ không xác định khi đọc file!";
        return false;
    }
}


bool Signature::resizeFile(const std::string &filePath, unsigned long long size)
{
    std::filesystem::path path = std::filesystem::u8path(filePath);
    try {
        std::filesystem::resize_file(path, size);
    } catch (const std::filesystem::filesystem_error& e) {
        return false;
    }
    return true;
}

QString Signature::verifyTokens(const std::string &filePath) const
{
    QJsonObject resultJson;
    if (interCACer.empty() || tokenCer.empty() || signature.empty() || fileSize.empty()) {
        resultJson["status"] = "File chưa được xác thực tin cậy";
        return QString(QJsonDocument(resultJson).toJson(QJsonDocument::Compact));
    }

    X509_STORE* trustStore = RootCATrustStore::getTrustStore();
    if (!trustStore) {
        resultJson["status"] = "Có lỗi xảy ra khi xác thực văn bản!";
        return QString(QJsonDocument(resultJson).toJson(QJsonDocument::Compact));
    }

    QJsonArray checks;
    bool allOk = true;

    for (int i = static_cast<int>(tokenCer.size()) - 1; i >= 0; --i) {
        // Resize file
        if (!resizeFile(filePath, fileSize[i])) {
            allOk = false;
            QJsonObject entry;
            entry["index"] = i;
            entry["subject"] = "Unknown";
            entry["status"] = "Resize failed";
            checks.append(entry);
            continue;
        }

        // Load interCA
        const unsigned char* p = reinterpret_cast<const unsigned char*>(interCACer[i].constData());
        X509* interX509 = d2i_X509(nullptr, &p, interCACer[i].size());
        if (!interX509) {
            allOk = false;
            QJsonObject entry;
            entry["index"] = i;
            entry["subject"] = "Unknown";
            entry["status"] = "Không thể tìm thấy InterCA Certificate!";
            checks.append(entry);
            continue;
        }

        // Load tokenCer
        p = reinterpret_cast<const unsigned char*>(tokenCer[i].constData());
        X509* tokenX509 = d2i_X509(nullptr, &p, tokenCer[i].size());
        if (!tokenX509) {
            allOk = false;
            X509_free(interX509);
            QJsonObject entry;
            entry["index"] = i;
            entry["subject"] = "Unknown";
            entry["status"] = "Không thể tìm thấy Token Certificate!";
            checks.append(entry);
            continue;
        }

        // Tạo danh sách untrusted
        STACK_OF(X509)* untrusted = sk_X509_new_null();
        sk_X509_push(untrusted, interX509);

        // Verify token certificate
        X509_STORE_CTX* ctxToken = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctxToken, trustStore, tokenX509, untrusted);
        bool sigCertOk = (X509_verify_cert(ctxToken) == 1);

        X509_STORE_CTX_free(ctxToken);
        sk_X509_free(untrusted);

        // Verify file signature
        QFile file(QString::fromStdString(filePath));
        if (!file.open(QIODevice::ReadOnly)) {
            sigCertOk = false;
        }
        QByteArray fileData = file.readAll();
        file.close();

        EVP_PKEY* pubKey = X509_get_pubkey(tokenX509);
        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        bool sigOk = false;
        if (EVP_DigestVerifyInit(mdCtx, nullptr, EVP_sha256(), nullptr, pubKey) == 1) {
            if (EVP_DigestVerify(mdCtx,
                                 reinterpret_cast<const unsigned char*>(signature[i].constData()),
                                 signature[i].size(),
                                 reinterpret_cast<const unsigned char*>(fileData.constData()),
                                 fileData.size()) == 1) {
                sigOk = true;
            }
        }
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pubKey);

        // Lấy subject
        X509_NAME* subj = X509_get_subject_name(tokenX509);
        char buf[256];
        X509_NAME_oneline(subj, buf, sizeof(buf));

        QJsonObject entry;
        entry["index"] = i;
        entry["subject"] = QString::fromUtf8(buf);
        entry["status"] = (sigCertOk && sigOk) ? "Verified" : "Failed";
        checks.append(entry);

        if (!(sigCertOk && sigOk)) allOk = false;

        X509_free(tokenX509);
        X509_free(interX509);
    }

    resultJson["checks"] = checks;
    resultJson["conclusion"] = allOk ? "Văn bản đáng tin cậy" : "Văn bản đã bị chỉnh sửa";

    return QString(QJsonDocument(resultJson).toJson(QJsonDocument::Compact));
}

