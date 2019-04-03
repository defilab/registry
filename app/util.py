import asyncio
import random
import re
import string
import time
from concurrent.futures import ThreadPoolExecutor as Executor

import pytz


def timestamp():
    return int(time.time())


def validate_email(email):
    return re.match(r'^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$', email)


def isotime(dt):
    return dt.replace(tzinfo=pytz.utc).isoformat()


def generate_password(length=32):
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(length)])


loop = asyncio.new_event_loop()
def batch_async_call(named_calls=None, max_workers=6):
    if not named_calls:
        return {}

    async def runner(calls):
        names = sorted(calls.keys())
        with Executor(max_workers=max_workers) as executor:
            futures = [
                loop.run_in_executor(
                    executor,
                    calls[name],
                )
                for name in names
            ]
            results = await asyncio.gather(*futures)
            return dict(zip(names, results))

    return loop.run_until_complete(runner(named_calls))
