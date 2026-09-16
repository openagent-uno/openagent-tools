"""Execution packages run without importing the agent engine."""
import asyncio
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

from openagent_execution import LocalBackend, ProcessCodeExecutor, DockerBackend, DockerConfig


class ExecutionTests(unittest.IsolatedAsyncioTestCase):
    def executor(self,environment):
        return ProcessCodeExecutor(backend=LocalBackend(environment=environment),
            python_executable=sys.executable, bridge_transport='unix', isolated=False,environment=environment)

    async def test_two_instances_have_explicit_environments_and_close_independently(self):
        environment={'MARKER':'first'}
        first=self.executor(environment)
        environment['MARKER']='changed'
        second=self.executor({'MARKER':'second'})
        command=shlex.quote(sys.executable)+' -c '+shlex.quote('import os; print(os.getenv("MARKER")); print(os.getenv("AMBIENT_CANARY"))')
        with patch.dict(os.environ,{'AMBIENT_CANARY':'not forwarded'}):
            results=await asyncio.gather(*(e.run(command=command,cwd=None,env=e.environment,
                timeout_seconds=2,context=None) for e in (first,second)))
        self.assertEqual([r.stdout for r in results],['first\nNone\n','second\nNone\n'])
        await first.close()
        with self.assertRaises(RuntimeError): await first.prepare(None)
        result=await second.run(command=command,cwd=None,env=second.environment,timeout_seconds=2,context=None)
        self.assertEqual(result.exit_code,0)
        await second.close()

    async def test_cancellation_kills_child_before_late_effect(self):
        executor=self.executor({})
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/'must-not-exist'
            code=f'import time; from pathlib import Path; time.sleep(0.3); Path({str(marker)!r}).touch()'
            command=shlex.quote(sys.executable)+' -c '+shlex.quote(code)
            task=asyncio.create_task(executor.run(command=command,cwd=directory,env={},timeout_seconds=5,context=None))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError): await task
            await asyncio.sleep(0.4)
            self.assertFalse(marker.exists())
        await executor.close()

    async def test_remote_backend_never_selects_local_rpc_or_ambient_environment(self):
        with patch.dict(os.environ,{'OPENAGENT_SANDBOX_BACKEND':'unrecognized','PRIVATE_KEY':'secret'}):
            backend=DockerBackend(DockerConfig(),environment={'PATH':'/usr/bin:/bin'})
            with self.assertRaises(ValueError):
                ProcessCodeExecutor(backend=backend,python_executable='python3',bridge_transport='unix',
                    isolated=True,environment={})
            backend._cid='fixture-only'
            spec=backend.build_spawn(command='echo fixture',cwd=None,env={})
            self.assertNotIn('PRIVATE_KEY',spec.env)
            self.assertNotIn('secret',spec.argv)
            backend._cid=None


if __name__=='__main__': unittest.main()
