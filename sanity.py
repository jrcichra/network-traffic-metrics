#!/usr/bin/python3
import asyncio


async def one():
    while True:
        await asyncio.sleep(1)
        print("one")


async def five():
    while True:
        await asyncio.sleep(5)
        print("five")


loop = asyncio.get_event_loop()
tasks = [
    loop.create_task(one()),
    loop.create_task(five()),
]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
