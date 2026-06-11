import asyncio
from leak_data_integration.core.analyzer import LeakAnalyzer


async def test():
    analyzer = LeakAnalyzer()
    res = await analyzer.test_connection()
    print(f"Connection test result: {res}")
    if res:
        print("Success")
    else:
        print("Failed")

if __name__ == "__main__":
    asyncio.run(test())
