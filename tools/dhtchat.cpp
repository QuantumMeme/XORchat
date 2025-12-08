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
#include <cctype>
#include <future>
#include <chrono>
#include <condition_variable>
#include <unordered_map>

using namespace dht;

static std::mt19937_64 rd {dht::crypto::getSeededRandomEngine<std::mt19937_64>()};
static std::uniform_int_distribution<dht::Value::Id> rand_id;


// for simplicity's sake. All users on one list :)
const static InfoHash USER_LIST_KEY = InfoHash::get("userlist");

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

// this took a dumb amount of time
static std::map<std::string,std::string> load_simple_conf(const std::string& confpath)
{
    std::map<std::string, std::string> out;
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

/* STARTING IDENTITY STUFF */


enum class UserStatus : uint8_t
{
    Offline = 0,
    Online = 1,
    Away = 2,
    Busy = 3
};

struct UserInfo
{
    std::string nickname {};
    std::string pubkey {};
    UserStatus status {UserStatus::Offline};
    std::string channel {};
    std::time_t last_seen {0}; // heartbeat timestamp (unix epoch)
};


// jsons are actually super complicated for no reason so we'll do this 
// Format per line: name|pubkey|status|channel|last_seen\n

static std::string serialize_user_list(const UserInfo& user)
{
    std::ostringstream oss;
    oss << user.nickname << '|' << user.pubkey << '|' << static_cast<unsigned>(user.status) << '|' << user.channel << '|' << user.last_seen << "\n";
    return oss.str();
}


static std::map<std::string, UserInfo> parse_user_list(const std::string& serialized)
{
    std::map<std::string, UserInfo> result;
    std::istringstream iss(serialized);
    std::string line;

    while (std::getline(iss, line))
    {
        if (line.empty())
            continue;

        std::istringstream line_stream(line);
        std::string nickname, pubkey, status_str, channel, last_seen_str;

        if (std::getline(line_stream, nickname, '|')
            && std::getline(line_stream, pubkey, '|')
            && std::getline(line_stream, status_str, '|')
            && std::getline(line_stream, channel, '|')
            && std::getline(line_stream, last_seen_str))
        {
            try {
                auto status_val = static_cast<uint8_t>(std::stoul(status_str));
                std::time_t last_seen = 0;
                try { last_seen = static_cast<std::time_t>(std::stoll(last_seen_str)); } catch(...) { last_seen = 0; }
                UserInfo ident {nickname, pubkey, static_cast<UserStatus>(status_val), channel, last_seen};
                result[nickname] = std::move(ident);
            } catch (const std::exception&){ continue; }
        }    
    }
    return result;
}


static std::unordered_map<std::string, UserInfo> pull_userlist(dht::DhtRunner& dht, const InfoHash& key = USER_LIST_KEY)
{
    auto promise = std::make_shared<std::promise<std::unordered_map<std::string, UserInfo>>>();
    auto future = promise->get_future();

    dht.get(key, [promise](const std::vector<std::shared_ptr<dht::Value>>& values) {
        std::unordered_map<std::string, UserInfo> aggregated;
        for (const auto& value : values) {
            std::string content(value->data.begin(), value->data.end());
            auto parsed = parse_user_list(content);
            for (auto& [name, user] : parsed) {
                if (user.pubkey.empty())
                    continue;
                auto iter = aggregated.find(user.pubkey);
                if (iter == aggregated.end() || user.last_seen > iter->second.last_seen) {
                    aggregated[user.pubkey] = std::move(user);
                }
            }
        }
        try {
            promise->set_value(std::move(aggregated));
        } catch (...) {}
        return false;
    }, [promise](bool ok) {
        if (not ok) {
            try { promise->set_value({}); } catch(...) {}
        }
    });

    if (future.wait_for(std::chrono::seconds(2)) == std::future_status::ready) {
        try {
            return future.get();
        } catch(...) {
            return {};
        }
    }
    return {};
}

static bool userlist_to_file(const std::unordered_map<std::string, UserInfo>& users, const std::string& path)
{
    std::ofstream ofs(path, std::ios::trunc);

    if (!ofs) {
        std::cerr << path << " not found" << std::endl;
        return false;
    }

    for (const auto& kv : users) {
        const auto& pubkey = kv.first;
        const auto& info = kv.second;
        ofs << pubkey << '|' << info.nickname << '|' << static_cast<unsigned>(info.status) << '|' << info.channel << '|' << info.last_seen << "\n";
    }
    ofs.close();

    return true;
}

static std::string announcement(std::string usernick, bool joined)
{
    std::string msg = "";
    if (joined)
        msg = usernick + " has joined.\n";
    else
        msg = usernick + " has left.\n";

    return msg;
}


class DhtIdentity {
    public:
        DhtIdentity(dht::DhtRunner& dht, std::string nickname, std::string pubkey)
            : dht_(dht), nickname_(std::move(nickname)), pubkey_(std::move(pubkey)),
            user_list_key_(USER_LIST_KEY)
        {
            // make id separate to pubkey
            user_list_value_id_ = static_cast<dht::Value::Id>(std::hash<std::string>{}(pubkey_));

            refresh_from_dht();
            set_status(UserStatus::Offline);

            // start heartbeat thread
            heartbeat_interval_seconds_ = 5;

            heartbeat_stop_.store(false);
            heartbeat_thread_ = std::thread([this]() {
                this->heartbeat_loop();
            });
        }

        ~DhtIdentity() {
            heartbeat_stop_.store(true);
            heartbeat_cv_.notify_all();
            if (heartbeat_thread_.joinable())
                heartbeat_thread_.join();
            // mark offline on destruction/pid exit
            try {
                mark_offline();
            } catch(...) {}
        }

        void set_status(UserStatus status)
        {
            update_entry([status](UserInfo& entry) { entry.status = status; }, false);
        }

        void mark_offline()
        {
            set_status(UserStatus::Offline);
        }

        void set_channel(const std::string& channel)
        {
            update_entry([&channel](UserInfo& entry) { entry.channel = channel; }, false);
        }


    private:
        void refresh_from_dht()
        {
            // https://en.cppreference.com/w/cpp/memory/shared_ptr/make_shared.html
            // thank the Lord for auto typing.
            auto promise = std::make_shared<std::promise<std::map<std::string, UserInfo>>>();
            auto future = promise->get_future();

            dht_.get(user_list_key_, [promise](const std::vector<std::shared_ptr<dht::Value>>& values)
            {
                std::map<std::string, UserInfo> aggregated;
                for (const auto& value : values) {
                    std::string content(value->data.begin(), value->data.end());
                    auto parsed = parse_user_list(content);
                    for (auto& [name, user] : parsed) {
                        // prefer the most recent last_seen
                        auto it = aggregated.find(name);
                        if (it == aggregated.end() || user.last_seen > it->second.last_seen) {
                            aggregated[name] = std::move(user);
                        }
                    }
                }
                try {
                    promise->set_value(std::move(aggregated));
                } catch (...) {}
                return false;
            }, [promise](bool ok) {
                if (!ok) {
                    try {
                        promise->set_value({});
                    } catch (...) {}
                }
            });

            if (future.wait_for(std::chrono::seconds(2)) == std::future_status::ready) {
                std::lock_guard<std::mutex> lock(mutex_);
                user_list_ = future.get();
            }
        }

        // void ensure_pubkey_unique()
        // {
        //     std::lock_guard<std::mutex> lock(mutex_);
        //     for (const auto& [name, user] : user_list_) {
        //         if (user.pubkey == pubkey_ && name != nickname_) {
        //             throw std::runtime_error("Public key already registered for another user");
        //         }
        //     }
        // }

        template<typename Fn>
        void update_entry(Fn updater, bool immediate)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& [name, user] : user_list_) {
                if (user.pubkey == pubkey_ && name != nickname_) {
                    throw std::runtime_error("Public key already registered for another user");
                }
            }
            auto& entry = user_list_[nickname_];
            entry.nickname = nickname_;
            entry.pubkey = pubkey_;
            updater(entry);

            // always update last_seen when we modify the entry
            entry.last_seen = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            if (immediate)
                publish_locked();
        }

        void publish_locked()
        {
            auto it = user_list_.find(nickname_); // ensures entry is ours
            if (it == user_list_.end()) return;
            auto payload = serialize_user_list(it->second);
            dht::Value value(payload);
            value.id = user_list_value_id_;
            dht_.putSigned(user_list_key_, std::move(value), [](bool ok) {
                if (!ok)
                    std::cerr << "Failed to publish user entry to DHT" << std::endl;
            });
        }

        void heartbeat_loop()
        {
            std::unique_lock<std::mutex> lk(heartbeat_mutex_);
            while (!heartbeat_stop_.load())
            {
                // update only our own entry's last_seen
                try {
                    update_entry([](UserInfo& entry){ /* no-op for other fields */ }, true);
                } catch (const std::exception& e) {
                    std::cerr << "Heartbeat update failed: " << e.what() << std::endl;
                }
                // wait for interval or stop
                heartbeat_cv_.wait_for(lk, std::chrono::seconds(heartbeat_interval_seconds_), [this](){ return heartbeat_stop_.load(); });
                if (heartbeat_stop_.load()) break;
            }
        }

        dht::DhtRunner& dht_;
        std::string nickname_ {};
        std::string pubkey_ {};
        dht::InfoHash user_list_key_;
        dht::Value::Id user_list_value_id_ {};
        std::map<std::string, UserInfo> user_list_;
        std::mutex mutex_;

        // heartbeat control
        std::thread heartbeat_thread_;
        std::atomic_bool heartbeat_stop_{false};
        std::mutex heartbeat_mutex_;
        std::condition_variable heartbeat_cv_;
        unsigned long heartbeat_interval_seconds_ {5};
};



static void print_usage() {
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
    std::string identity_prefix;

    bool has_config = false;

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

        
        // file prefix
        std::string safe_nick = nick;
        for (auto &c: safe_nick) if (!isalnum((unsigned char)c)) c = '_';
        identity_prefix = ident_dir + "/" + safe_nick;

        // save minimal conf for next run
        std::map<std::string,std::string> cfg;
        cfg["nick"] = nick;
        cfg["identity_prefix"] = identity_prefix;
        save_simple_conf(conf_file, cfg);

        params.generate_identity = true;
        params.save_identity = identity_prefix;

    } else {
        
        // config exists: load conf and ensure identity_prefix is present
        auto cfg = load_simple_conf(conf_file);
        if (cfg.find("identity_prefix") != cfg.end()) {
            has_config = true;
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

        identity_prefix = cfg["identity_prefix"];
        // std::cout << identity_prefix << std::endl;
    }

    DhtRunner dht;
    try {
        //params.generate_identity = true;

        //std::string ident_file = identity_prefix;

        if (has_config)
        {
            crypto::Identity ident = crypto::loadIdentity(identity_prefix);
            params.id = ident;
        }

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

        std::cout << "Welcome, " << nick << "!" << std::endl;

        DhtIdentity identity_manager(dht, nick, dht.getId().toString());

        print_node_info(dht.getNodeInfo());
        std::cout << "  type '/c {hash}' to join a channel" << std::endl << std::endl;

        bool connected {false};
        InfoHash room;
        std::future<size_t> token;

        const InfoHash myid = dht.getId();

#ifndef _MSC_VER
        // using the GNU History API
        using_history();
#endif

        // chat loop
        while (true)
        {
            // using the GNU Readline API
            std::string line = readLine(connected ? PROMPT : "> ");
            if (!line.empty() && line[0] == '\0')
                break;
            if (line.empty())
                continue;

            std::istringstream iss(line);
            std::string op, cmd, idstr;
            std::uint8_t stat;
            iss >> op;

            if (op.std::string::find('/') != std::string::npos) {
                cmd = op.substr(1);
                if (!connected) {

                    // quitting while disconnected
                    if (cmd  == "x" || cmd == "q")
                        break;
                        
                    // joining channels
                    else if (cmd == "c") {
                        iss >> idstr;
                        room = InfoHash(idstr);
                        if (not room) {
                            room = InfoHash::get(idstr);
                            std::cout << "Joining h(" << idstr << ") = " << room << std::endl;
                        }

                        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());


                        identity_manager.set_channel(room.toString());
                        identity_manager.set_status(UserStatus::Online);

                        token = dht.listen<dht::ImMessage>(room, [&](dht::ImMessage&& msg) {
                            if (msg.from != myid)
                                std::cout << msg.from.toString() << " at " << printTime(msg.date)
                                        << " (took " << print_duration(std::chrono::system_clock::now() - std::chrono::system_clock::from_time_t(msg.date))
                                        << ") " << (msg.to == myid ? "ENCRYPTED ":"") << ": " << msg.id << " - " << msg.msg << std::endl;
                            return true;
                        });

                        connected = true;
                        
                        dht.putSigned(room, dht::ImMessage(rand_id(rd), std::move(announcement(nick, true)), now), [](bool ok) {
                            if (not ok)
                                std::cout << "Message publishing failed !" << std::endl;
                        });

                    } else {
                        std::cout << "Unknown command. Type '/c {hash}' to join a channel" << std::endl << std::endl;
                    }
                } else {
                    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                    if (cmd == "d") {
                        std::cout << "Disconnecting from channel." << std::endl;
                        dht.putSigned(room, dht::ImMessage(rand_id(rd), std::move(announcement(nick, false)), now), [](bool ok) {
                            if (not ok)
                                std::cout << "Message publishing failed !" << std::endl;
                        });
                        dht.cancelListen(room, std::move(token));
                        connected = false;
                        identity_manager.set_channel("");
                        identity_manager.mark_offline();
                        continue;
                    } else if (cmd == "e") {
                        iss >> idstr;
                        std::getline(iss, line);
                        dht.putEncrypted(room, InfoHash(idstr), dht::ImMessage(rand_id(rd), std::move(line), now), [](bool ok) {
                            //dht.cancelPut(room, id);
                            if (not ok)
                                std::cout << "Message publishing failed !" << std::endl;
                        });
                    } else if (cmd == "s") { 
                        iss >> idstr;
                        try
                        {
                            stat = std::stoi(cmd);
                            if (stat > 0 && stat <= 3)
                                identity_manager.set_status(static_cast<UserStatus>(stat));
                            else
                                std::cout << cmd << " is not a valid status." << std::endl;
                        }
                        catch(const std::exception& e)
                        {
                            std::cerr << e.what() << '\n';
                            continue;
                        }
                        
                    } else if (cmd == "l") {
                        std::cout << "Saving userlist." << std::endl;
                        std::unordered_map<std::string, UserInfo> list = pull_userlist(dht);
                        userlist_to_file(list, get_default_config_dir() + "/users.txt");
                    }
                }            
            } else {         
                    if (connected) {
                        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                        dht.putSigned(room, dht::ImMessage(rand_id(rd), std::move(line), now), [](bool ok) {
                            
                            if (not ok)
                                std::cout << "Message publishing failed !" << std::endl;
                        });
                    } else {
                        std::cout << "You're not connected." << std::endl;
                    }
            }
        }
        identity_manager.mark_offline();
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
