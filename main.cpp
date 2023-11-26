#define _CRT_SECURE_NO_WARNINGS //解决scanf函数报错
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <signal.h>
#include <map>
#include <string>
#include <chrono>
#include <thread>

#include <WinSock2.h>
#include <Windows.h>
#include <pcap.h>

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"WS2_32.lib")

using namespace std;

#define ETH_ARP      0x0806   // 以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE 1        // 硬件类型字段值为表示以太网地址
#define ETH_IP       0x0800   // 协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST  1        // ARP请求
#define ARP_RESPONSE 2        // ARP应答

//14字节以太网首部
struct EthernetHeader
{
	u_char DestMAC[6];    // 目的MAC地址 6字节
	u_char SourMAC[6];    // 源MAC地址 6字节
	u_short EthType;      // 上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp 2字节
};

//28字节ARP帧结构
struct ArpHeader
{
	unsigned short hdType;    // 硬件类型
	unsigned short proType;   // 协议类型
	unsigned char hdSize;     // 硬件地址长度
	unsigned char proSize;    // 协议地址长度
	unsigned short op;        // 操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	u_char smac[6];           // 源MAC地址
	DWORD sip;                // 源IP地址
	u_char dmac[6];           // 目的MAC地址
	DWORD dip;                // 目的IP地址
};

//定义整个arp报文包，总长度42字节
struct ArpPacket {
	EthernetHeader ed;
	ArpHeader ah;
};

// 定义一个map来存储IP-MAC映射关系
std::map<std::string, std::string> arpTable;









// 发送arp请求
bool arpRequest(pcap_t* handle, char* ip) {

	// 报文内容
	ArpPacket ArpRequestPacket;
	// 将DestMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		ArpRequestPacket.ed.DestMAC[i] = 0xff;
	// 将SourMAC设置为本机网卡的MAC地址
	u_char sourceMac[] = { 0x14, 0x5A, 0xFC, 0x1C, 0x34, 0x77 };
	memcpy(ArpRequestPacket.ed.SourMAC, sourceMac, sizeof(sourceMac));
	// 将smac设置为本机网卡的MAC地址
	memcpy(ArpRequestPacket.ah.smac, sourceMac, sizeof(sourceMac));
	// 将sip设置为本机网卡上绑定的IP地址
	ArpRequestPacket.ah.sip = inet_addr("10.130.98.120");
	// 将dmac设置为0
	for (int i = 0; i < 6; i++)
		ArpRequestPacket.ah.dmac[i] = 0;
	// 将dip设置为请求的IP地址
	ArpRequestPacket.ah.dip = inet_addr(ip);
	

	ArpRequestPacket.ed.EthType = htons(0x806); //帧类型为ARP
	ArpRequestPacket.ah.hdType = htons(0x0001); //硬件类型为以太网
	ArpRequestPacket.ah.proType = htons(0x0800);//协议类型为IP
	ArpRequestPacket.ah.hdSize = 6;             //硬件地址长度为6
	ArpRequestPacket.ah.proSize = 4;            //协议地址长为4
	ArpRequestPacket.ah.op = htons(0x0001);     //操作为ARP请求

	// 发送数据包
	if (pcap_sendpacket(handle, (u_char*)&ArpRequestPacket, sizeof(ArpPacket))) {
		printf("  arp请求失败\n");
		return false;
	}
	
	
	// 维护一个计时器，最多等待一定时间
	auto startTime = std::chrono::high_resolution_clock::now(); 
	// 接收arp响应
	while (1)
	{
		pcap_pkthdr* pkt_header;  // 数据包头部信息
		const u_char* pkt_data;   // 数据包内容
		int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);  // 尝试捕获下一个数据包
		if (rtn == 1)
		{
			ArpPacket* ArpRecvPacket = (ArpPacket*)pkt_data;  // 将捕获的数据包内容强制类型转换为ARP数据包
			if (ntohs(ArpRecvPacket->ed.EthType) == 0x806)    // 检查数据包的帧类型是否为 ARP（0x806） 
			{
					// 输出ip
					struct in_addr sourceIP;
					sourceIP.s_addr = ArpRecvPacket->ah.sip;
					printf("  IP: %s -> ", inet_ntoa(sourceIP));
					// 输出MAC
					printf(" MAC: ");
					for (int i = 0; i < 6; i++)
					{
						printf("%02x.", ArpRecvPacket->ed.SourMAC[i]);
					}
					printf("\n");

					// 将收到的IP-MAC映射存储到表中
					std::string ipStr = inet_ntoa(sourceIP);
					std::string macStr;
					for (int i = 0; i < 6; i++) {
						char buffer[3];
						sprintf(buffer, "%02x", ArpRecvPacket->ed.SourMAC[i]);
						macStr += buffer;
						if (i < 5) {
							macStr += ":";
						}
					}
					arpTable[ipStr] = macStr;

					// 判断是否为目标IP的ARP响应，如果是则停止循环
					if (ArpRecvPacket->ah.sip == inet_addr(ip)) {
						break;
					}
			}
		}

		// 计算经过的时间
		auto currentTime = std::chrono::high_resolution_clock::now();
		auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();
		// 如果超过一定时间，则结束循环
		if (elapsedTime > 10000) {
			printf("  超时，未收到目标ARP响应\n");
			return false;
		}
		// 等待一段时间再继续循环，以免过于频繁地检查
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	return true;
}















int enumAdapters()
{
	pcap_if_t* allAdapters;    // 所有网卡设备保存
	pcap_if_t* ptr;            // 用于遍历的指针
	int index = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 获取本地机器设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
	{
		/* 打印网卡信息列表 */
		for (ptr = allAdapters; ptr != NULL; ptr = ptr->next)
		{
			++index;
			if (ptr->description)
				printf("ID: %d --> Name: %s \n", index, ptr->description);

			//获取该网络接口设备的ip地址信息
			for (pcap_addr* a = ptr->addresses; a != nullptr; a = a->next)
			{
				if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
				{
					// 打印ip地址
					printf("%s\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				}
			}
		}
	}
	/* 不再需要设备列表了，释放它 */
	pcap_freealldevs(allAdapters);
	return index;
}

pcap_t* catchAdapters(int n)
{
	pcap_if_t* adapters;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &adapters, errbuf) != -1)
	{
		//找到指定网卡
		for (int i = 1; i < n && adapters->next != NULL; i++) {
			adapters = adapters->next;
		}
		//打开指定网卡
		char errbuf2[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open(adapters->name, 65534, 1, PCAP_OPENFLAG_PROMISCUOUS, 0, 0); // PCAP_OPENFLAG_PROMISCUOUS = 网卡设置为混杂模式
		pcap_freealldevs(adapters);
		return handle;
	}
}











int main(int argc, char* argv[])
{
	int network = enumAdapters();
	int destination_network;
	printf("网卡数量: %d \n", network);
	printf("选择网卡：");
	scanf("%d", &destination_network);

	pcap_t* handle = catchAdapters(destination_network);
	
	while (1) {
		printf("\n输入目的ip：");
		char ip[INET_ADDRSTRLEN];
		scanf("%s", ip);
		// 查找IP-MAC映射表
		auto it = arpTable.find(ip);
		if (it != arpTable.end()) {
			// 如果在表中找到了，直接使用表中的映射
			printf("在表中找到IP-MAC映射：IP: %s, MAC: %s\n", it->first.c_str(), it->second.c_str());
		}
		else {
			// 如果表中没有找到，执行ARP请求
			struct in_addr addr;
			if (inet_pton(AF_INET, ip, &addr) == 1) {
				char* charIp = inet_ntoa(addr);
				// printf("转换后的IP地址: %s\n", charIp);
			}
			else {
				printf("无效的IP地址格式\n");
				continue;  // 重新循环，要求输入有效的IP地址
			}

			// 维护一个计数器，最多请求3次
			int count = 0;
			while (count < 3) {
				printf("arp请求%d: \n", count + 1);
				if (arpRequest(handle, ip)) break;
				else count++;
			}
		}
	}
	

	system("Pause");
}
