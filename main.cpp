#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <unistd.h>
#include <tins/sniffer.h>
#include <tins/dot11.h>
#include <algorithm>


struct settings {
    std::string interface = "wlan0";
    bool monitor = false;
    bool beep = false;
    std::vector<std::string> whitelist;
    bool fuckoff = false;
    int threshold = 1;
};

struct device {
    std::string bssid;
    int deauthpktcount = 0;
};


std::vector<device> devices;
settings dd_settings;


void _help(){
    std::cout << "usage: ./dd [arguments]" << std::endl;
    std::cout << "\t-h\t--help\t\tthis" << std::endl;
    std::cout << "\t-i\t--interface\twifi interface to use" << std::endl;
    std::cout << "\t-m\t--monitor\tuse monitor mode" << std::endl;
    std::cout << "\t-b\t--beep\t\tbeep if attacked" << std::endl;
    std::cout << "\t-w\t--whitelist\ta comma separated list of bssids" << std::endl;
    std::cout << "\t-f\t--fuckoff\tsend packets to attacker" << std::endl;
    std::cout << "\t-t\t--threshold\tamount of packets to trigger" << std::endl;
    exit(0);
}

std::vector<std::string> parse_whitelist(std::string arg){
    std::vector<std::string> whitelist;
    std::size_t s = 0, e = 0;
    while((e = arg.find(',', s)) != std::string::npos){
        whitelist.push_back(arg.substr(s, e - s));
        s = e + 1;
    }
    whitelist.push_back(arg.substr(s));
    return whitelist;
}

bool pdu_processor(Tins::PDU& pdu){
    const Tins::Dot11Deauthentication& deauth = pdu.rfind_pdu<Tins::Dot11Deauthentication>();
    if(dd_settings.whitelist.size() > 0){
        if(std::find(dd_settings.whitelist.begin(), dd_settings.whitelist.end(), deauth.addr2().to_string()) != dd_settings.whitelist.end())
            std::cout << "whitelisted device " << deauth.addr2().to_string() << " sent deauth frame" << std::endl;
    } else {
        auto it = std::find_if(devices.begin(), devices.end(), [&](const device& d) {return d.bssid == deauth.addr2().to_string();});
        if(it != devices.end()) it.base()->deauthpktcount++;
        else {
            device d;
            d.bssid = deauth.addr2().to_string();
            d.deauthpktcount++;
            devices.push_back(d);
        }
        it = std::find_if(devices.begin(), devices.end(), [&](const device& d) {return d.deauthpktcount >= dd_settings.threshold;});
        if(it != devices.end()){
            std::cout << deauth.addr2().to_string() << " triggered after reaching deauth threshold" << std::endl;
            if(dd_settings.beep) std::cout << '\a';
            // todo fuckoff
        }
    }

    return true;
}

void signal_handler(int p){
    std::cout << std::endl << "caught sig-int/kill/ill; freeing memory and shutting down" << std::endl;
    std::cout << "bye bye" << std::endl;
    exit(0);
}

void check_root(){
    if(geteuid() != 0){
        std::cout << "please run with root" << std::endl;
        exit(0);
    }
}

int main(int argc, char** argv) {
    signal(SIGINT, signal_handler);
    signal(SIGKILL, signal_handler);
    signal(SIGILL, signal_handler);

    std::cout << "deauthdetect" << std::endl;

    for(int i = 0; i < argc; i++){
        std::string arg(argv[i]);
        if(arg == "-h" || arg == "--help") _help();
        if(arg == "-m" || arg == "--monitor") dd_settings.monitor = true;
        if(arg == "-b" || arg == "--beep") dd_settings.beep = true;
        if(arg == "-w" || arg == "--whitelist") dd_settings.whitelist = parse_whitelist(std::string(argv[i + 1]));
        if(arg == "-f" || arg == "--fuckoff") dd_settings.fuckoff = true;
        if(arg == "-t" || arg == "--threshold") dd_settings.threshold = atoi(argv[i + 1]);
    }

    check_root();

    std::cout << "threshold is " << dd_settings.threshold << std::endl;
    std::cout << "using interface " << dd_settings.interface << std::endl;
    if(dd_settings.whitelist.size() > 0){
        std::cout << "whitelist:" << std::endl;
        for(int i = 0; i < dd_settings.whitelist.size(); i++) std::cout << "\t" << dd_settings.whitelist.at((unsigned long)i) << std::endl;
    } else std::cout << "not using the whitelist" << std::endl;
    if(dd_settings.beep) std::cout << "gonna make noise" << std::endl;
    if(dd_settings.fuckoff) std::cout << "gonna tell the attacker to fuck off" << std::endl;
    if(dd_settings.monitor) std::cout << "using monitor mode" << std::endl;

    Tins::SnifferConfiguration sc;
    sc.set_promisc_mode(dd_settings.monitor);
    Tins::Sniffer s(dd_settings.interface, sc);
    std::cout << "sniffing.." << std::endl;
    s.sniff_loop(pdu_processor);
    return 0;
}