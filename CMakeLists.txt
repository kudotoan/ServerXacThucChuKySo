cmake_minimum_required(VERSION 3.16)

project(ServerXacThuc LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(OpenSSL_INCLUDE_DIR "D:/Program File/OpenSSL-Win64/include")
set(OpenSSL_LIB_DIR "D:/Program File/OpenSSL-Win64/lib/VC/x64/MT")

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Sql)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Sql)
include_directories("${OpenSSL_INCLUDE_DIR}")
link_directories("${OpenSSL_LIB_DIR}")
add_executable(ServerXacThuc
  main.cpp
  model/signature.h model/signature.cpp
  model/databasemanager.h model/databasemanager.cpp
  model/rootcatruststore.h model/rootcatruststore.cpp
)
target_link_libraries(ServerXacThuc Qt${QT_VERSION_MAJOR}::Core Qt6::Sql libssl.lib libcrypto.lib ws2_32)

include(GNUInstallDirs)
install(TARGETS ServerXacThuc
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
