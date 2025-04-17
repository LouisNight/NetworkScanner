#include <iostream>
#include <vector>
#include <sstream>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <thread>
#include <mutex>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

std::mutex outputMutex;

bool isHostAlive(const std::string& ip) {
    IPAddr destIP;
    inet_pton(AF_INET, ip.c_str(), &destIP);

    BYTE macAddr[6];
    ULONG macAddrLen = sizeof(macAddr);

    return SendARP(destIP, 0, macAddr, &macAddrLen) == NO_ERROR;
}

std::string resolveHostname(const std::string& ip) {
    struct sockaddr_in sa;
    char hostname[NI_MAXHOST];

    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));

    if (getnameinfo((sockaddr*)&sa, sizeof(sa), hostname, NI_MAXHOST, nullptr, 0, 0) == 0) {
        return std::string(hostname);
    }
    else {
        return "Hostname not found";
    }
}

std::string ipToString(uint32_t ip) {
    struct in_addr ip_addr;
    ip_addr.S_un.S_addr = htonl(ip);
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr, buffer, INET_ADDRSTRLEN);
    return std::string(buffer);
}

std::vector<std::string> generateIPRange(const std::string& ipStr, const std::string& subnetStr) {
    in_addr ip_addr, subnet_addr;
    inet_pton(AF_INET, ipStr.c_str(), &ip_addr);
    inet_pton(AF_INET, subnetStr.c_str(), &subnet_addr);

    uint32_t ip = ntohl(ip_addr.S_un.S_addr);
    uint32_t mask = ntohl(subnet_addr.S_un.S_addr);

    uint32_t network = ip & mask;
    uint32_t broadcast = network | (~mask);

    std::vector<std::string> ipList;
    for (uint32_t current = network + 1; current < broadcast; ++current) {
        ipList.push_back(ipToString(current));
    }
    return ipList;
}

bool getLocalIPAddressAndSubnet(std::string& outIP, std::string& outSubnet) {
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &bufferSize);
    IP_ADAPTER_ADDRESSES* adapterAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    if (!adapterAddresses) return false;

    if (GetAdaptersAddresses(AF_INET, 0, nullptr, adapterAddresses, &bufferSize) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES* adapter = adapterAddresses; adapter != nullptr; adapter = adapter->Next) {
            for (IP_ADAPTER_UNICAST_ADDRESS* address = adapter->FirstUnicastAddress; address != nullptr; address = address->Next) {
                SOCKADDR_IN* sa_in = (SOCKADDR_IN*)address->Address.lpSockaddr;

                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, INET_ADDRSTRLEN);
                outIP = ipStr;

                ULONG prefixLength = address->OnLinkPrefixLength;
                ULONG mask = (0xFFFFFFFF << (32 - prefixLength)) & 0xFFFFFFFF;
                in_addr subnetAddr;
                subnetAddr.S_un.S_addr = htonl(mask);

                char subnetStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &subnetAddr, subnetStr, INET_ADDRSTRLEN);
                outSubnet = subnetStr;

                free(adapterAddresses);
                return true;
            }
        }
    }

    free(adapterAddresses);
    return false;
}

void scanIP(const std::string& ip) {
    if (isHostAlive(ip)) {
        std::string hostname = resolveHostname(ip);

        std::lock_guard<std::mutex> lock(outputMutex);
        std::cout << ip << " is ONLINE - Hostname: " << hostname << "\n";
    }
}

int main() {
    std::string localIP, subnet;
    if (!getLocalIPAddressAndSubnet(localIP, subnet)) {
        std::cerr << "Could not retrieve local IP and subnet.\n";
        return 1;
    }

    std::cout << "===== Local Network Info =====\n";
    std::cout << "Local IP Address : " << localIP << "\n";
    std::cout << "Subnet Mask      : " << subnet << "\n\n";

    std::cout << "===== Generating IP Range =====\n";
    std::vector<std::string> ipList = generateIPRange(localIP, subnet);
    for (const auto& ip : ipList) {
        std::cout << ip << "\n";
    }

    std::cout << "\n===== Scanning for Online Devices =====\n";

    std::vector<std::thread> threads;
    for (const auto& ip : ipList) {
        threads.emplace_back(scanIP, ip);
    }

    for (auto& t : threads) {
        t.join();
    }

    std::cout << "\n===== Scan Complete =====\n";
    return 0;
}
