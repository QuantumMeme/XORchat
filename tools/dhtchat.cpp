/*
 *  Copyright (C) 2014-2025 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tools_common.h"
#include <opendht/rng.h>

extern "C" {
#include <gnutls/gnutls.h>
}
#include <ctime>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <map>
#include <atomic>
#include <thread>
#include <mutex>
#include <utility>
#include <iostream>

using namespace dht;

static std::mt19937_64 rd {dht::crypto::getSeededRandomEngine<std::mt19937_64>()};
static std::uniform_int_distribution<dht::Value::Id> rand_id;

const std::string printTime(const std::time_t& now) {
    struct tm tstruct = *localtime(&now);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
}

// creating environment for config file. we'll use this to store nicknames and identities. and whatever settings we want.
static std::string get_default_config_dir()
{
    const char* xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) {
        return std::string(xdg) + "/xorchat";
    }
    const char* home = getenv("HOME");
    if (home && *home) {
        return std::string(home) + "/.xorchat";
    }
    return std::string(".xorchat");
}

// just making these easier to access
static bool dir_exists(const std::string& path)
{
    try {
        std::filesystem::create_directories(path);
        return true;
    } catch (...) {
        return false;
    }
}

static bool file_exists(const std::string& path)
{
    return std::filesystem::exists(path);
}

//if we want more files then it'll be just storing mapped string pairs. i miss dicts :(
static void save_simple_conf(const std::string& confpath, const std::map<std::string,std::string>& map)
{
    std::ofstream of(confpath, std::ios::trunc);
    for (auto &p : map)
        of << p.first << "=" << p.second << "\n";
    of.close();
}


static std::map<std::string,std::string> load_simple_conf(const std::string& confpath)
{
    std::map<std::string,std::string> out;
    std::ifstream ifs(confpath);
    if (!ifs) return out;
    std::string line;
    while (std::getline(ifs, line)) {
        auto pos = line.find('=');
        if (pos != std::string::npos) {
            auto key = line.substr(0, pos);
            auto val = line.substr(pos+1);
            out[key] = val;
        }
    }
    return out;
}

void print_usage() {
    std::cout << "Usage: dhtchat [-n network_id] [-p local_port] [-b bootstrap_host[:port]]" << std::endl << std::endl;
    std::cout << "dhtchat, a simple OpenDHT command line chat client." << std::endl;
    std::cout << "Report bugs to: https://opendht.net" << std::endl;
}

int
main(int argc, char **argv)
{
    auto params = parseArgs(argc, argv);
    if (params.help) {
        print_usage();
        return 0;
    }
#ifdef _MSC_VER
    if (auto err = gnutls_global_init()) {
        std::cerr << "Failed to initialize GnuTLS: " << gnutls_strerror(err) << std::endl;
        return EXIT_FAILURE;
    }
#endif

    // Checking for configuration files
    std::string config_dir = get_default_config_dir();
    std::string ident_dir = config_dir + "/ident";
    std::string conf_file = config_dir + "/xorchat.conf";

    if (!file_exists(config_dir) || !file_exists(ident_dir)) {
    // create structure and create initial config
        if (!dir_exists(ident_dir)) {
            std::cerr << "Failed to create config directories at " << config_dir << std::endl;
            return EXIT_FAILURE;
        }
        // prompt for nickname and generate identity
        std::string nick;
        std::cout << "Welcome to XORchat! Let's get you logged in." << std::endl;
        std::cout << "Enter your nickname: ";
        std::getline(std::cin, nick);
        // if no nickname, you get a timestamp username. sucks for you
        if (nick.empty()) nick = std::string("user_") + std::to_string(std::time(nullptr));

        
        // Build an identity prefix path inside ident_dir, filename safe
        std::string safe_nick = nick;
        for (auto &c: safe_nick) if (!isalnum((unsigned char)c)) c = '_';
        std::string identity_prefix = ident_dir + "/" + safe_nick;

        // Save minimal conf so next run reuses
        std::map<std::string,std::string> cfg;
        cfg["nick"] = nick;
        cfg["identity_prefix"] = identity_prefix;
        save_simple_conf(conf_file, cfg);

        // Make sure params instruct generation+save
        params.generate_identity = true;
        params.save_identity = identity_prefix;

    } else {

        // config exists: load conf and ensure identity_prefix is present
        auto cfg = load_simple_conf(conf_file);
        if (cfg.find("identity_prefix") != cfg.end()) {
            params.save_identity = cfg["identity_prefix"];
        } else {
            if (cfg.find("nick") == cfg.end()) {
                std::string nick;
                std::cout << "Enter your nickname: ";
                std::getline(std::cin, nick);
                if (nick.empty()) nick = std::string("user_") + std::to_string(std::time(nullptr));
                cfg["nick"] = nick;
                save_simple_conf(conf_file, cfg);
            }
        }       
    }

    DhtRunner dht;
    try {
        params.generate_identity = true;
        auto dhtConf = getDhtConfig(params);
        dht.run(params.port, dhtConf.first, std::move(dhtConf.second));

        if (not params.bootstrap.empty())
            dht.bootstrap(params.bootstrap);

        // load nickname
        std::string nick;
        auto cfg = load_simple_conf(conf_file);
        if (cfg.find("nick") != cfg.end())
            nick = cfg["nick"];
        else
            nick = "xorchatter";

        std::cout << "Welcome, " << nick << "!";

        print_node_info(dht.getNodeInfo());
        std::cout << "  type 'c {hash}' to join a channel" << std::endl << std::endl;

        bool connected {false};
        InfoHash room;
        std::future<size_t> token;

        const InfoHash myid = dht.getId();

#ifndef _MSC_VER
        // using the GNU History API
        using_history();
#endif

        while (true)
        {
            // using the GNU Readline API
            std::string line = readLine(connected ? PROMPT : "> ");
            if (!line.empty() && line[0] == '\0')
                break;
            if (line.empty())
                continue;

            std::istringstream iss(line);
            std::string op, idstr;
            iss >> op;
            if (not connected) {
                if (op  == "x" || op == "q" || op == "exit" || op == "quit")
                    break;
                else if (op == "c") {
                    iss >> idstr;
                    room = InfoHash(idstr);
                    if (not room) {
                        room = InfoHash::get(idstr);
                        std::cout << "Joining h(" << idstr << ") = " << room << std::endl;
                    }

                    token = dht.listen<dht::ImMessage>(room, [&](dht::ImMessage&& msg) {
                        if (msg.from != myid)
                            std::cout << msg.from.toString() << " at " << printTime(msg.date)
                                      << " (took " << print_duration(std::chrono::system_clock::now() - std::chrono::system_clock::from_time_t(msg.date))
                                      << ") " << (msg.to == myid ? "ENCRYPTED ":"") << ": " << msg.id << " - " << msg.msg << std::endl;
                        return true;
                    });
                    connected = true;
                } else {
                    std::cout << "Unknown command. Type 'c {hash}' to join a channel" << std::endl << std::endl;
                }
            } else {
                auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                if (op == "d") {
                    dht.cancelListen(room, std::move(token));
                    connected = false;
                    continue;
                } else if (op == "e") {
                    iss >> idstr;
                    std::getline(iss, line);
                    dht.putEncrypted(room, InfoHash(idstr), dht::ImMessage(rand_id(rd), std::move(line), now), [](bool ok) {
                        //dht.cancelPut(room, id);
                        if (not ok)
                            std::cout << "Message publishing failed !" << std::endl;
                    });
                } else if (op == "/") {
                    std::cout << "we'll make this work eventually lol" << std::endl;
                } else {         

                    dht.putSigned(room, dht::ImMessage(rand_id(rd), std::move(line), now), [](bool ok) {
                        
                        if (not ok)
                            std::cout << "Message publishing failed !" << std::endl;
                    });
                }
            }
        }
    } catch(const std::exception&e) {
        std::cerr << std::endl <<  e.what() << std::endl;
    }

    std::cout << std::endl <<  "Stopping node..." << std::endl;
    dht.join();
#ifdef _MSC_VER
    gnutls_global_deinit();
#endif
    return 0;
}
