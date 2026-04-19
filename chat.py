import asyncio
import hashlib
import json
import os
import signal
import sys
import threading
import json as _json

from setowire import Swarm

SEED_FILE_TEMPLATE = './identity.{nick}.json'


def _seed_file_for(nick: str) -> str:
    safe = ''.join(ch for ch in nick if ch.isalnum() or ch in ('-', '_')).lower()
    if not safe:
        safe = 'default'
    return SEED_FILE_TEMPLATE.format(nick=safe)


def _load_or_create_seed(nick: str) -> str:
    seed_file = _seed_file_for(nick)
    if os.path.exists(seed_file):
        with open(seed_file) as f:
            return json.load(f)['seed']
    seed = os.urandom(32).hex()
    with open(seed_file, 'w') as f:
        json.dump({'seed': seed}, f)
    return seed


def _ts() -> str:
    import datetime
    now = datetime.datetime.now()
    return f'{now.hour:02d}:{now.minute:02d}'


def _sys(msg: str):
    print(f'\x1b[90m[{_ts()}] * {msg}\x1b[0m')


def _msg(nick: str, from_nick: str, text: str):
    color = '\x1b[32m' if from_nick == nick else '\x1b[35m'
    print(f'\x1b[90m[{_ts()}]\x1b[0m {color}{from_nick}\x1b[0m: {text}')


async def main():
    args = sys.argv[1:]
    if not args:
        print('usage: python -m p2p_swarm.chat <nick> [room]')
        sys.exit(1)

    nick = args[0]
    room = args[1] if len(args) > 1 else 'general'
    seed = _load_or_create_seed(nick)

    swarm    = Swarm({'seed': seed})
    topic    = hashlib.sha256(f'chat:{room}'.encode()).digest()
    nicks    = {}
    handshook = set()

    _sys(f'starting... nick={nick} room={room}')

    swarm.on('nat',     lambda: _sys(f'nat={swarm.nat_type} addr={swarm.public_address or "LAN"}'))
    swarm.on('nattype', lambda: _sys(f'nat type refined: {swarm.nat_type}'))

    def _send_join(peer):
        try:
            peer.write(json.dumps({'type': 'JOIN', 'nick': nick}).encode())
        except Exception:
            pass

    def on_connection(peer):
        ev = asyncio.get_event_loop()
        _send_join(peer)
        ev.call_later(0.4, lambda p=peer: _send_join(p))
        ev.call_later(1.2, lambda p=peer: _send_join(p))

    swarm.on('connection', on_connection)

    def on_data(data: bytes, peer):
        try:
            m = json.loads(data)
        except Exception:
            return

        if m.get('_selfId') == swarm._id:
            return

        if m.get('type') == 'JOIN':
            fresh = peer.id not in nicks
            nicks[peer.id] = m['nick']
            if fresh:
                _sys(f"{m['nick']} joined")
            if peer.id not in handshook:
                handshook.add(peer.id)
                _send_join(peer)
            return

        if m.get('type') == 'MSG':
            _msg(nick, m['nick'], m['text'])
            return

        if m.get('type') == 'LEAVE':
            _sys(f"{nicks.get(peer.id) or m.get('nick')} left")
            nicks.pop(peer.id, None)

    swarm.on('data', on_data)

    def on_disconnect(peer_id: str):
        name = nicks.get(peer_id) or peer_id[:8]
        _sys(f'{name} disconnected')
        nicks.pop(peer_id, None)
        handshook.discard(peer_id)

    swarm.on('disconnect', on_disconnect)

    await swarm.join(topic, announce=True, lookup=True)
    _sys(f'ready | nat={swarm.nat_type} | addr={swarm.public_address or "LAN"}')

    loop = asyncio.get_event_loop()
    shutdown = asyncio.Event()
    _quitting  = False

    async def _shutdown():
        nonlocal _quitting
        if _quitting:
            return
        _quitting = True
        payload = json.dumps({'type': 'LEAVE', 'nick': nick}).encode()
        swarm.broadcast(payload)
        await asyncio.sleep(0.3)
        try:
            await swarm.destroy()
        finally:
            shutdown.set()

    def _sigint_handler():
        asyncio.ensure_future(_shutdown())

    try:
        loop.add_signal_handler(signal.SIGINT, _sigint_handler)
    except NotImplementedError:
        signal.signal(signal.SIGINT, lambda *_: loop.call_soon_threadsafe(_sigint_handler))

    def _handle_input(line: str):
        text = line.strip()
        if not text:
            return

        if text == '/peers':
            _sys(f'{swarm.size} peer(s) connected')
            for p in swarm.peers:
                _sys(f'  {p.id[:8]} nick={nicks.get(p.id, "?")} rtt={round(p.rtt)}ms mesh={p.in_mesh}')
            return

        if text == '/nat':
            _sys(f'nat={swarm.nat_type} addr={swarm.public_address or "LAN"}')
            return

        if text == '/quit':
            asyncio.ensure_future(_shutdown())
            return

        payload = json.dumps({'type': 'MSG', 'nick': nick, 'text': text, '_selfId': swarm._id}).encode()
        if not swarm.broadcast(payload):
            for p in swarm.peers:
                if p._session:
                    p.write(payload)
        _msg(nick, nick, text)

    loop.call_later(0.5, lambda: _sys('commands: /peers  /nat  /quit'))

    stdin_queue: asyncio.Queue[str | None] = asyncio.Queue()
    stdin_stop = threading.Event()

    def _start_stdin_thread():
        def _run():
            while not stdin_stop.is_set():
                line = sys.stdin.readline()
                if not line:
                    loop.call_soon_threadsafe(stdin_queue.put_nowait, None)
                    break
                loop.call_soon_threadsafe(stdin_queue.put_nowait, line)

        t = threading.Thread(target=_run, daemon=True)
        t.start()

    reader = None
    if os.name == 'nt':
        _start_stdin_thread()
    else:
        reader = asyncio.StreamReader()
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)

    print(f'\x1b[32m{nick}\x1b[0m > ', end='', flush=True)

    while not shutdown.is_set():
        try:
            if os.name == 'nt':
                done, pending = await asyncio.wait(
                    {asyncio.create_task(stdin_queue.get()), asyncio.create_task(shutdown.wait())},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for p in pending:
                    p.cancel()
                finished = next(iter(done)).result()
                if finished is True:
                    break
                line = finished
                if line is None:
                    break
            else:
                done, pending = await asyncio.wait(
                    {asyncio.create_task(reader.readline()), asyncio.create_task(shutdown.wait())},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for p in pending:
                    p.cancel()
                finished = next(iter(done)).result()
                if finished is True:
                    break
                raw = finished
                if not raw:
                    break
                line = raw.decode()

            _handle_input(line)
            print(f'\x1b[32m{nick}\x1b[0m > ', end='', flush=True)
        except (EOFError, KeyboardInterrupt, asyncio.CancelledError):
            break

    stdin_stop.set()
    if not shutdown.is_set():
        await _shutdown()


if __name__ == '__main__':
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
