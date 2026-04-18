import asyncio
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, '.')

from app.core.pipeline import run_pipeline

async def test():
    url = 'http://paypal-verify-secure.xyz/login/confirm?user=verify'
    result = await run_pipeline(url, skip_cache=True)
    print(f'\nScore: {result.score}')
    print(f'Verdict: {result.verdict}')
    print(f'\nFlags with score > 0:')
    for f in result.flags:
        if f.score > 0:
            print(f'  [{f.severity}] {f.type}: +{f.score}')
    print(f'\nTop Reasons:')
    for i, r in enumerate(result.reasons[:3], 1):
        print(f'  {i}. {r[:80]}')

asyncio.run(test())
