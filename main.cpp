/*
    author : Sai Tharun
*/

#include "pch.h"
#include <iostream>
#include "WebCrawling.h"

using namespace std;

class WebCrawling;
CRITICAL_SECTION queueCriticalSection;
CRITICAL_SECTION hostCriticalSection;
CRITICAL_SECTION ipCriticalSection;
CRITICAL_SECTION activeThreadsCriticalSection;
CRITICAL_SECTION statsCriticalSection;

class Parameters {
public:
    queue<char*> links;
    set<DWORD> seen_IP;
    set<string> seen_hosts;
    int active_threads;
    int extracted_urls;
    int unique_hosts;
    int dns_lookups;
    int unique_ips;
    int robot_checks;
    vector<int>status_codes;
    int total_links_found;
    HANDLE	eventQuit;
    int pages;
    int bytes;
    int total_bytes;
    vector<int>total_tamu_links;
    int tamu_domain;
    int non_tamu_domain;
};

void crawl(Parameters*p, char* link, HTMLParserBase*&parser) {
   
    WebCrawling obj;
    int length = strlen(link) + 1;
    char* original_link = new char[length];
    strcpy_s(original_link, length, link);

    char* host = NULL;
    char* fragment = NULL;
    char* query = NULL;
    char* path = NULL;
    char* port_string = NULL;
    int port = 0;

    char* head_path = new char[12];
    strcpy_s(head_path, 12, "/robots.txt");
    char* head_query = new char[2];
    strcpy_s(head_query, 2, "");

    bool success = obj.clean_url(fragment, query, path, port_string, port, host, link);
    if (success) {

        EnterCriticalSection(&statsCriticalSection);
        p->extracted_urls++;
        LeaveCriticalSection(&statsCriticalSection);

        EnterCriticalSection(&hostCriticalSection);
        auto host_check = p->seen_hosts.insert(host);
        LeaveCriticalSection(&hostCriticalSection);
        
        if(obj.print) printf("\tChecking host uniqueness...");

        if (host_check.second == true)
        {
            EnterCriticalSection(&statsCriticalSection);
            p->unique_hosts++;
            LeaveCriticalSection(&statsCriticalSection);
            if (obj.print) printf("passed\n");
           
            obj.DNS_LOOKUP(host, port);
            
            if (!obj.error) {

                EnterCriticalSection(&statsCriticalSection);
                p->dns_lookups++;
                LeaveCriticalSection(&statsCriticalSection);

                if (obj.print) printf("\tChecking IP uniqueness...");
                EnterCriticalSection(&ipCriticalSection);
                auto ip_result = p->seen_IP.insert(inet_addr(inet_ntoa(obj.server.sin_addr)));
                LeaveCriticalSection(&ipCriticalSection);

                if (ip_result.second == true)
                {
                    EnterCriticalSection(&statsCriticalSection);
                    p->unique_ips++;
                    LeaveCriticalSection(&statsCriticalSection);
                    if (obj.print) printf("passed\n");
                }
                else {
                    if (obj.print) printf("failed\n");
                    obj.error = true;
                }   
            }
            if (!obj.error) {
                obj.head_request(port, host, head_path, head_query, original_link);
                EnterCriticalSection(&statsCriticalSection);
                p->bytes += obj.head_buffer_size;
                LeaveCriticalSection(&statsCriticalSection);
            }

            if (!obj.error) {
                EnterCriticalSection(&statsCriticalSection);
                p->robot_checks++;
                LeaveCriticalSection(&statsCriticalSection);
                int code = obj.get_request(port, host, path, query, original_link);
                EnterCriticalSection(&statsCriticalSection);
                if (code >= 200 && code < 300) p->status_codes[0]++;
                else if (code >= 300 && code < 400) p->status_codes[1]++;
                else if (code >= 400 && code < 500) p->status_codes[2]++;
                else if (code >= 500 && code < 600) p->status_codes[3]++;
                else if (code != -1) p->status_codes[4]++;                
                p->pages++;
                p->bytes += obj.get_buffer_size;
                LeaveCriticalSection(&statsCriticalSection);
            }

            if (!obj.error) {
                int nlinks = obj.parse_response(original_link, parser);
                EnterCriticalSection(&statsCriticalSection);
                p->total_links_found += nlinks;
                //TAMU hosts
                if (strlen(host) >= 8 && strcmp(host + strlen(host) - 8, "tamu.edu") == 0) {

                    if (obj.tamu_links > 0) p->tamu_domain++;
                    p->total_tamu_links[0] += obj.tamu_links;
                }
                //NON TAMU hosts
                else {
                    p->total_tamu_links[1] += obj.tamu_links;
                    if (obj.tamu_links > 0) p->non_tamu_domain++;
                }
                LeaveCriticalSection(&statsCriticalSection);
            }
        }
        else {
            if (obj.print) printf("failed\n");
        }
    }

    delete[] fragment;
    delete[] query;
    delete[] path;
    delete[] port_string;
    delete[] original_link;
    delete[] head_path;
    delete[] head_query;
    delete[] link;
}

UINT crawling_thread(LPVOID pParam)
{
    Parameters* p = ((Parameters*)pParam);
    HTMLParserBase* parser = new HTMLParserBase;

    while (true)
    {
        EnterCriticalSection(&queueCriticalSection);
        if (p->links.size() == 0) {
            LeaveCriticalSection(&queueCriticalSection);
            break;
        }
        char* link = p->links.front();
        p->links.pop();
        LeaveCriticalSection(&queueCriticalSection);
        crawl(p, link, parser);
    }

    delete parser;

    EnterCriticalSection(&activeThreadsCriticalSection);
    p->active_threads--;
    LeaveCriticalSection(&activeThreadsCriticalSection);

    return 0;
}

UINT stats_thread(LPVOID pParam)
{
    Parameters* p = ((Parameters*)pParam);
    clock_t start, small_start, small_end;;
    start = clock();
    small_start = clock();
    while (WaitForSingleObject(p->eventQuit, 2000) == WAIT_TIMEOUT)
    {
        small_end = clock();
        int d = (small_end - small_start) / 1000;
        int elapsed_time = clock() - start;

        int size = p->links.size();
        
        int active_threads = p->active_threads;
        
        int extracted_urls = p->extracted_urls;
        int unique_hosts = p->unique_hosts;
        int dns_lookups = p->dns_lookups;
        int unique_ips = p->unique_ips;
        int robot_checks = p->robot_checks;
        int crawled_urls = p->status_codes[0] + p->status_codes[1] + p->status_codes[2] + p->status_codes[3] + p->status_codes[4];
        int total_links_found = p->total_links_found;
        int pages = p->pages;
        int bytes = p->bytes;
        p->total_bytes += bytes;
        p->pages = 0;
        p->bytes = 0;

        total_links_found = ceil(total_links_found / 1000);

        float speed = (((float)bytes * 8.0 / 1000000.0)) / (float) d;
        printf("[%3d] %d Q %6d E %7d H %6d D %6d I %5d R %5d C %5d L %4dK\n", elapsed_time/1000, active_threads, size, extracted_urls, unique_hosts, dns_lookups, unique_ips, robot_checks, crawled_urls, total_links_found);
        printf("*** crawling %d pps @ %.2f Mbps\n", pages / d, speed);
        small_start = clock();
    }

    int elapsed_time = (clock() - start) / 1000;
    int crawled_urls = p->status_codes[0] + p->status_codes[1] + p->status_codes[2] + p->status_codes[3] + p->status_codes[4];

    printf("\n");
    printf("Extracted %d URLS @ %d/s\n", p->extracted_urls, p->extracted_urls / elapsed_time);
    printf("Looked up %d DNS names @ %d/s\n", p->unique_hosts, p->unique_hosts / elapsed_time);
    printf("Attempted %d robots @ %d/s\n", p->unique_ips, p->unique_ips / elapsed_time);
    printf("Crawled %d pages @ %d/s (%.2f MB)\n", crawled_urls, p->status_codes[0] / elapsed_time, (float)p->total_bytes/1000000.0 );
    printf("Parsed %d links @ %d/s\n", p->total_links_found, p->total_links_found / elapsed_time);
    printf("HTTP codes: 2xx = %d, 3xx = %d, 4xx = %d, 5xx = %d, other = %d\n", p->status_codes[0], p->status_codes[1], p->status_codes[2], p->status_codes[3], p->status_codes[4]);
    //printf("TAMU Hosts links %d : %d, NON TAMU hosts links %d: %d", p->tamu_domain, p->total_tamu_links[0],p->non_tamu_domain, p->total_tamu_links[1]);
    return 0;
}

bool read_links_from_file(char* filename, queue<char*>&links) {
 
    ifstream file(filename);
    string line;

    if (!file.is_open()) {
        printf("Error reading file\n");
        return true;
    }

    while (getline(file, line)) {
        char* temp = new char[line.length() + 1];
        strcpy(temp, line.c_str());
        links.push(temp);
    }

    //Getting file size
    //TODO: figure out out to get filesize with in one go
    file.clear();
    file.seekg(0, ios::end);
    int file_size = file.tellg();

    printf("Opened %s with size %d\n", filename, file_size);

    file.close();

    return false;
}

int main(int argc, char** argv)
{
    WSADATA wsaData;
     
    //Initialize WinSock; once per program run 
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        printf("WSAStartup failed with %d\n", WSAGetLastError());
        WSACleanup();
        return 0;
    }

    if (argc == 2) {
        char* link = argv[1];
        WebCrawling obj;
        obj.is_part_one = true;
        obj.print = true;
        int length = strlen(link) + 1;
        char* original_link = new char[length];
        strcpy_s(original_link, length, link);

        char* host = NULL;
        char* fragment = NULL;
        char* query = NULL;
        char* path = NULL;
        char* port_string = NULL;
        int port = 0;

        bool success = obj.clean_url(fragment, query, path, port_string, port, host, link);
        if (success) {
            obj.DNS_LOOKUP(host, port);
            if(!obj.error) obj.get_request_HTTP_1(port, host, path, query, original_link);
            if (!obj.error) {
                HTMLParserBase* parser = new HTMLParserBase;
                obj.parse_response(original_link, parser, true);
                delete parser;
            }
        }
    }
    else if (argc == 3)
    {
        queue<char*>links;
        HANDLE* handles = NULL;
        int threads;
        Parameters p;

        char* temp = argv[1];
        threads = atoi(temp);
        if (threads < 1) {
            printf("Please pass valid number of threads and name of file as 2 arguments\n");
            return 0;  
        }
        handles = new HANDLE[threads];
        if (!InitializeCriticalSectionAndSpinCount(&queueCriticalSection,
            0x00000400) || !InitializeCriticalSectionAndSpinCount(&hostCriticalSection,
                0x00000400) || !InitializeCriticalSectionAndSpinCount(&ipCriticalSection,
                    0x00000400) || !InitializeCriticalSectionAndSpinCount(&activeThreadsCriticalSection,
                        0x00000400) || !InitializeCriticalSectionAndSpinCount(&statsCriticalSection,
                            0x00000400))
            return 0;
        
        char* filename = argv[2];
        bool error = read_links_from_file(filename, links);
        if(error) return 0;
        p.active_threads = 0;
        p.links = links;
        p.extracted_urls = 0;
        p.unique_hosts = 0;
        p.dns_lookups = 0;
        p.unique_ips = 0;
        p.robot_checks = 0;
        p.total_links_found = 0;
        p.status_codes = { 0,0,0,0,0 };
        p.pages = 0;
        p.bytes = 0;
        p.total_bytes = 0;
        p.total_tamu_links = { 0,0 };
        p.tamu_domain = 0;
        p.non_tamu_domain = 0;
        p.eventQuit = CreateEvent(NULL, true, false, NULL);

        HANDLE stats_thread_handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)stats_thread, &p, 0, NULL);
        p.active_threads = threads;

        SetThreadPriority(stats_thread_handle, THREAD_PRIORITY_HIGHEST);

        for (int i = 0; i < threads; i++)
        {
            handles[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)crawling_thread, &p, 0, NULL);
        }
        // make sure this thread hangs here until the other three quit; otherwise, the program will terminate prematurely
        for (int i = 0; i < threads; i++)
        {
            WaitForSingleObject(handles[i], INFINITE);
            CloseHandle(handles[i]);
        }

        SetEvent(p.eventQuit);

        WaitForSingleObject(stats_thread_handle, INFINITE);
        CloseHandle(stats_thread_handle);
    }
    else {
        printf("Please pass only URL in format -> scheme://host[:port][/path][?query][#fragment]\n");
        printf("OR\n");
        printf("Please pass only 1 thread and name of file as 2 arguments\n");
    }

   DeleteCriticalSection(&queueCriticalSection);
   DeleteCriticalSection(&hostCriticalSection);
   DeleteCriticalSection(&ipCriticalSection);
   DeleteCriticalSection(&activeThreadsCriticalSection); 
   DeleteCriticalSection(&statsCriticalSection);

   WSACleanup();
}

