import asyncio


async def p(n):
    while True:
        print(n)
        #在python的协程中想要sleep的话必须使用 asyncio的sleep
        await asyncio.sleep(1)

async def main():
    for i in range(1000000):
        await p(i)
        asyncio.create_task(p(i))
    await asyncio.sleep(10000)

asyncio.run(main())
# asyncio.run(main())
