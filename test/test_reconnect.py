import asyncio

from App.core.RedisConnector import RedisClient


def test_redis_client_reconnects_when_disconnected():
    client = RedisClient()

    async def scenario():
        client._client = object()
        client._is_connected = False

        async def fake_connect():
            client._client = "redis-ready"
            client._is_connected = True

        client.connect = fake_connect
        assert await client.ensure_connected() == "redis-ready"
        assert client._is_connected is True

    asyncio.run(scenario())
