import asyncio
import os
import socket
import unittest

from bond import CHUNK, WINDOW, Receiver, receive_stream, send_stream


class Ordering(unittest.TestCase):
    def test_gap_and_duplicate(self):
        rx = Receiver()
        self.assertEqual(rx.accept(1, b"b"), b"")
        self.assertEqual(rx.accept(1, b"b"), b"")
        self.assertEqual(rx.accept(0, b"a"), b"ab")
        self.assertEqual(rx.accept(0, b"a"), b"")
        with self.assertRaises(ValueError):
            rx.accept(WINDOW + 2, b"x")


class Transfer(unittest.IsolatedAsyncioTestCase):
    async def test_two_directions(self):
        writers = []
        async def pair():
            sockets = socket.socketpair()
            ends = [await asyncio.open_connection(sock=s) for s in sockets]
            writers.extend(w for _, w in ends)
            return ends

        try:
            lanes = [await pair() for _ in range(3)]
            for direction in (0, 1):
                outgoing = [p[direction] for p in lanes]
                incoming = [p[1-direction] for p in lanes]
                source = asyncio.StreamReader()
                data = os.urandom(CHUNK * (WINDOW * 3 + 1) + 27)
                source.feed_data(data)
                source.feed_eof()
                sink, client = await pair()
                _, _, result = await asyncio.wait_for(asyncio.gather(
                    send_stream(source, outgoing), receive_stream(incoming, sink[1]),
                    client[0].read()), timeout=10)
                self.assertEqual(result, data)
        finally:
            for writer in writers:
                writer.close()
            await asyncio.gather(*(w.wait_closed() for w in writers))


if __name__ == "__main__":
    unittest.main()
