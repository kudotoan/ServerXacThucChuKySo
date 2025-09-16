#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <iostream>
#include <string>
#include <ctime>
#include <cstdlib>
#include "model/signature.h"
#include <QCoreApplication>
#include "model/databasemanager.h"
#include "model/rootcatruststore.h"
#include <QString>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#pragma comment(lib, "ws2_32.lib")
const size_t MAX_HEADER_SIZE = 16 * 1024;
struct PER_IO_OPERATION_DATA {
    OVERLAPPED overlapped;
    WSABUF wsaBuf;
    char buffer[4096];           // buffer nhận chunk
    std::string accum;
    size_t expected = 0;         // Content-Length
    size_t received = 0;
    FILE* fileHandle = nullptr;
    std::string filePath;
};

// Worker thread xử lý IOCP
DWORD WINAPI WorkerThread(LPVOID lpParam) {
    // qDebug() << "hehe";

    HANDLE hIOCP = (HANDLE)lpParam;
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    PER_IO_OPERATION_DATA* pIOData;

    while (true) {
        BOOL ok = GetQueuedCompletionStatus(
            hIOCP, &bytesTransferred, &completionKey,
            (LPOVERLAPPED*)&pIOData, INFINITE);
        SOCKET clientSock = (SOCKET)completionKey;

        if (!ok || bytesTransferred == 0) {

            if (pIOData && pIOData->fileHandle) fclose(pIOData->fileHandle);
            closesocket(clientSock);
            if (pIOData) delete pIOData;
            continue;
        }

        pIOData->accum.append(pIOData->buffer, bytesTransferred);

        if (pIOData->expected == 0 && pIOData->accum.size() > MAX_HEADER_SIZE) {
            std::string reply = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n" +
                                std::string(R"({"status":"Không thể đọc header, file này không hợp lệ"})");
            send(clientSock, reply.c_str(), (int)reply.size(), 0);

            closesocket(clientSock);
            if (pIOData->fileHandle) fclose(pIOData->fileHandle);
            delete pIOData;
            continue;
        }

        if (pIOData->expected == 0) {
            size_t headerEnd = pIOData->accum.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                size_t pos = pIOData->accum.find("Content-Length:");
                if (pos != std::string::npos) {
                    size_t endLine = pIOData->accum.find("\r\n", pos);
                    std::string lenStr = pIOData->accum.substr(pos + 15, endLine - (pos + 15));
                    pIOData->expected = std::stoul(lenStr);
                }

                //create folder XacThuc trong temp
                char tempPath[MAX_PATH];
                DWORD len = GetTempPathA(MAX_PATH, tempPath);
                if (len == 0 || len > MAX_PATH) strcpy_s(tempPath, ".");

                std::string dirXacThuc = std::string(tempPath) + "XacThuc\\";
                CreateDirectoryA(dirXacThuc.c_str(), NULL);

                std::srand((unsigned int)std::time(nullptr));
                std::time_t t = std::time(nullptr);
                int randNum = std::rand() % 10000;
                int suffix = 0;
                char filename[MAX_PATH];

                while (true) {

                    if (suffix == 0) {
                        std::snprintf(filename, sizeof(filename), "%s%lld_%04d.pdf",
                                      dirXacThuc.c_str(), static_cast<long long>(t), randNum);
                    } else {
                        std::snprintf(filename, sizeof(filename), "%s%lld_%04d_%02d.pdf",
                                      dirXacThuc.c_str(), static_cast<long long>(t), randNum, suffix);
                    }

                    FILE* fcheck = fopen(filename, "rb");
                    if (!fcheck) break;
                    fclose(fcheck);
                    suffix++;
                    if (suffix > 999) {
                        std::cerr << "Cannot create unique filename in XacThuc folder\n";
                        break;
                    }
                }

                pIOData->fileHandle = fopen(filename, "wb");
                if (!pIOData->fileHandle) {
                    std::cerr << "Cannot open temp file\n";
                    closesocket(clientSock);
                    delete pIOData;
                    continue;
                }
                pIOData->filePath = filename;

                std::string body = pIOData->accum.substr(headerEnd + 4);
                if (!body.empty()) {
                    fwrite(body.data(), 1, body.size(), pIOData->fileHandle);
                    pIOData->received = body.size();
                }
                pIOData->accum.clear();
            }
        } else {

            if (pIOData->fileHandle) {
                size_t toWrite = std::min(static_cast<size_t>(bytesTransferred), pIOData->expected - pIOData->received);
                fwrite(pIOData->buffer, 1, toWrite, pIOData->fileHandle);
                pIOData->received += toWrite;
            }
        }
        if (pIOData->expected > 0 && pIOData->received >= pIOData->expected) {
            fclose(pIOData->fileHandle);

            Signature sig;
            qint64 size;

            if (!Signature::loadLastFromFile(QString::fromStdString(pIOData->filePath), sig, size)) {
                QJsonObject resultJson;
                resultJson["status"] = "File không đúng định dạng .PDF hoặc đã bị chỉnh sửa!";
                QString jsonResult = QString(QJsonDocument(resultJson).toJson(QJsonDocument::Compact));
                std::string reply = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                                    std::string(jsonResult.toUtf8().constData());
                send(clientSock, reply.c_str(), (int)reply.size(), 0);
            } else {
                QString jsonResult = sig.verifyTokens(pIOData->filePath); // JSON trả về
                std::string reply = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                                    std::string(jsonResult.toUtf8().constData());
                send(clientSock, reply.c_str(), (int)reply.size(), 0);

            }
            closesocket(clientSock);
            std::remove(pIOData->filePath.c_str());

            delete pIOData;
            continue;
        }

        ZeroMemory(&pIOData->overlapped, sizeof(OVERLAPPED));
        DWORD flags = 0;
        pIOData->wsaBuf.buf = pIOData->buffer;
        pIOData->wsaBuf.len = sizeof(pIOData->buffer);
        WSARecv(clientSock, &pIOData->wsaBuf, 1, NULL, &flags,
                &pIOData->overlapped, NULL);
    }

    return 0;
}
int main(int argc, char *argv[]) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
    QCoreApplication app(argc, argv);

    if (!DatabaseManager::connect()) {
        qCritical() << "Cannot connect to database!";
        return 1;
    }

    X509_STORE* trustStore = RootCATrustStore::getTrustStore();



    SOCKET listenSock = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(2611);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(listenSock, (sockaddr*)&addr, sizeof(addr));
    listen(listenSock, SOMAXCONN);

    HANDLE hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    int numThreads = sysinfo.dwNumberOfProcessors;
    for (int i = 0; i < (int)(numThreads+(numThreads>>1)); ++i) {
        CreateThread(NULL, 0, WorkerThread, hIOCP, 0, NULL);
    }

    std::cout << "Server running on port 2611..." << std::endl;

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);

        CreateIoCompletionPort((HANDLE)clientSock, hIOCP, (ULONG_PTR)clientSock, 0);

        PER_IO_OPERATION_DATA* pIOData = new PER_IO_OPERATION_DATA;
        ZeroMemory(&pIOData->overlapped, sizeof(OVERLAPPED));
        pIOData->wsaBuf.buf = pIOData->buffer;
        pIOData->wsaBuf.len = sizeof(pIOData->buffer);
        DWORD flags = 0;
        WSARecv(clientSock, &pIOData->wsaBuf, 1, NULL, &flags,
                &pIOData->overlapped, NULL);
    }

    DatabaseManager::disconnect();
    WSACleanup();
    return 0;
}
