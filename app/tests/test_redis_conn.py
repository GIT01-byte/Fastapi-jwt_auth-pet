
import asyncio
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from auth.redis.client import get_redis_client

test_access_token = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.' \
    'eyJ0eXBlIjoicmVmcmVzaF90b2tlbiIsInN1YiI6IjEiLCJleHAiOjU0OTgxMjQyOTUsImlhdCI6MTc2NTY0NDI5NX0.' \
    'JaamTkV5JkPMj_xUjpPt0zUwLO-9QkoxOIN7XmQMkkD6QsV2DBV0buBzTWhtX5MizRCNqPwniJFS56wqP4kfCg'


async def test_redis_conn():
    conn = await get_redis_client()
    print(conn)
    await conn.setex('access_token', 10, test_access_token)
    access_token_in_redis = await conn.get('access_token')
    print(f"Test token: {access_token_in_redis}")
    print(f'Wait for exp redis access_token value -_-')
    await asyncio.sleep(10)
    exp_access_token_in_redis = await conn.get('access_token')
    print(f"Token: {exp_access_token_in_redis}")

if __name__ == "__main__":
    asyncio.run(test_redis_conn())
