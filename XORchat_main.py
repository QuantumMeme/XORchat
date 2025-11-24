import json
import sys
import threading
import time

import opendht


def infohash_from_string(s):
    try:
        return opendht.InfoHash.get(s)
    except Exception as e:
        print(f"Error computing InfoHash: {e}")
        return None


def print_message(msg, my_id):
    text = json.loads(msg.data.decode("utf-8"))

    # if text["sender"] != str(my_id):
    date_str = time.strftime('%Y-%m-%d %X', time.localtime(text["ts"]))
    print(f"\n{text["sender"]} at {date_str}: {text["txt"]}")
    sys.stdout.write("> ")
    sys.stdout.flush()


class DHTChat:
    def __init__(self, port=None, bootstrap="24.158.161.211:42450", network_id=0):
        self.dht = opendht.DhtRunner()
        self.port = port
        self.bootstrap = bootstrap
        self.network_id = network_id
        self.room = None
        self.token = None
        self.running = True

        self.identity = opendht._core.Identity.generate()

    def run(self):
        if self.port:
            self.dht.run(self.identity, self.port)
        else:
            self.dht.run(self.identity)
        if self.bootstrap:
            self.dht.bootstrap(self.bootstrap)
        print("Node Id:", self.dht.getId())
        print("Type 'c CHANNEL' to join a channel, 'q' to quit.")
        print("> ", end='', flush=True)
        while self.running:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.strip()
                if line in ('q', 'quit', 'exit', 'x'):
                    self.running = False
                    break
                elif line.startswith("c "):
                    _, chan = line.split(" ", 1)
                    room = infohash_from_string(chan)
                    self.join_channel(room)
                elif self.room:
                    # Send message to channel
                    msg_obj = {"sender": str(self.dht.getId()),
                               # "user": self.identity.public(),
                               "txt": line,
                               "ts": time.time()
                               }
                    self.dht.putSigned(self.room, opendht.Value(json.dumps(msg_obj).encode("utf-8")))
                else:
                    print("Join a channel first: c CHANNEL")
                print("> ", end='', flush=True)
            except KeyboardInterrupt:
                break
        self.dht.join()
        print("\nStopped.")

    def listen_thread(self, room):
        my_id = self.dht.getId()

        def handler(msg, room_l):
            print_message(msg, my_id)
            return True

        token = self.dht.listen(room, handler)
        while self.running:
            time.sleep(0.5)
        self.dht.cancel_listen(room, token)

    def join_channel(self, room):
        if not room:
            print("Invalid channel name/hash!")
            return
        self.room = room
        print(f"Joined channel: {room}")
        th = threading.Thread(target=self.listen_thread, args=(room,), daemon=True)
        th.start()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Python OpenDHT Chat")
    parser.add_argument("-p", "--port", type=int, default=52449, help="Local port")
    parser.add_argument("-b", "--bootstrap", type=str, default=None, help="Bootstrap host[:port]")
    parser.add_argument("-n", "--network", type=int, default=0, help="Network id")
    args = parser.parse_args()

    chat = DHTChat(port=args.port, bootstrap=args.bootstrap, network_id=args.network)
    chat.run()
