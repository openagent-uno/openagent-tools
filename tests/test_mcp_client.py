"""Official SDK sessions against an HTTP mock; no model, provider or credentials."""
import asyncio
import json
import unittest

import httpx

from openagent_mcp_client import MCPClientError, MCPRemoteError, MCPTransportError, MCPProtocolError, request


class Endpoint:
    def __init__(self):
        self.calls = []
        self.deny = False
        self.http_status = None
        self.bug = False
        self.pending = None
        self.entered = asyncio.Event()
        self.duplicate = False
        self.tool_error = False

    async def handle(self, incoming):
        body = json.loads(incoming.content)
        method = body['method']
        self.calls.append(method)
        if self.http_status:
            return httpx.Response(self.http_status, request=incoming)
        if method == 'notifications/initialized':
            return httpx.Response(202, request=incoming)
        result = {}
        if method == 'initialize':
            result = {'protocolVersion': body['params']['protocolVersion'], 'capabilities': {'tools': {}},
                      'serverInfo': {'name': 'host-a', 'version': '1'}}
        elif method == 'tools/list':
            tools = [{'name': 'inventory', 'description': 'Read authorized objects', 'inputSchema': {'type': 'object'}}]
            result = {'tools': tools * (2 if self.duplicate else 1)}
        elif method == 'tools/call':
            self.entered.set()
            if self.pending:
                await self.pending.wait()
            if self.bug:
                raise TypeError('synthetic programming bug')
            if self.deny:
                return httpx.Response(200, request=incoming, json={'jsonrpc': '2.0', 'id': body['id'],
                    'error': {'code': -32000, 'message': 'Object access denied'}})
            result = {'content': [{'type': 'text', 'text': '[]'}], 'isError': self.tool_error}
        return httpx.Response(200, request=incoming, json={'jsonrpc': '2.0', 'id': body['id'], 'result': result})

    def client(self, headers=None, timeout=None, auth=None):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle), headers=headers,
                                 timeout=timeout, auth=auth, trust_env=False, follow_redirects=False)


class ClientContracts(unittest.IsolatedAsyncioTestCase):
    async def test_remote_denial_is_typed_after_sdk_context_teardown_without_retry(self):
        endpoint = Endpoint(); endpoint.deny = True
        with self.assertRaises(MCPRemoteError) as caught:
            await request('http://host-a.invalid/mcp', operation='call', name='inventory',
                          http_client_factory=endpoint.client, timeout=2)
        self.assertEqual(-32000, caught.exception.code)
        self.assertEqual('Object access denied', caught.exception.remote_message)
        self.assertNotIn('Object access denied', str(caught.exception))
        self.assertEqual(1, endpoint.calls.count('tools/call'))

    async def test_http_denial_is_typed_transport_failure(self):
        endpoint = Endpoint(); endpoint.http_status = 403
        with self.assertRaises(MCPTransportError) as caught:
            await request('http://host-a.invalid/mcp', operation='list', http_client_factory=endpoint.client, timeout=2)
        self.assertEqual(403, caught.exception.http_status)
        self.assertEqual(1, len(endpoint.calls))

    async def test_cancellation_propagates_without_availability_conversion(self):
        endpoint = Endpoint(); endpoint.pending = asyncio.Event()
        task = asyncio.create_task(request('http://host-a.invalid/mcp', operation='call', name='inventory',
                                          http_client_factory=endpoint.client, timeout=2))
        await asyncio.wait_for(endpoint.entered.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(1, endpoint.calls.count('tools/call'))

    async def test_programming_error_is_not_normalized_or_hidden(self):
        endpoint = Endpoint(); endpoint.bug = True
        try:
            await request('http://host-a.invalid/mcp', operation='call', name='inventory',
                          http_client_factory=endpoint.client, timeout=2)
        except BaseException as error:
            self.assertNotIsInstance(error, MCPClientError)
            def leaves(value):
                return sum((leaves(x) for x in value.exceptions), []) if isinstance(value, BaseExceptionGroup) else [value]
            self.assertTrue(any(isinstance(x, TypeError) for x in leaves(error)))
        else:
            self.fail('Programming error was hidden')

    async def test_success_preserves_tool_result_and_bounded_catalog(self):
        endpoint = Endpoint()
        tools = await request('http://host-a.invalid/mcp', operation='list', http_client_factory=endpoint.client, timeout=2)
        self.assertEqual([{'name': 'inventory', 'description': 'Read authorized objects', 'input_schema': {'type': 'object'}}], tools)
        result = await request('http://host-a.invalid/mcp', operation='call', name='inventory', http_client_factory=endpoint.client, timeout=2)
        self.assertEqual('[]', result['content'][0]['text'])
        self.assertFalse(result['isError'])

    async def test_remote_ambiguous_catalog_fails_closed(self):
        endpoint = Endpoint(); endpoint.duplicate = True
        with self.assertRaises(MCPProtocolError):
            await request('http://host-a.invalid/mcp', operation='list', http_client_factory=endpoint.client, timeout=2)

    async def test_valid_tool_error_envelope_is_preserved_as_result(self):
        endpoint = Endpoint(); endpoint.tool_error = True
        result = await request('http://host-a.invalid/mcp', operation='call', name='inventory',
                               http_client_factory=endpoint.client, timeout=2)
        self.assertTrue(result['isError'])
        self.assertEqual(1, endpoint.calls.count('tools/call'))

    async def test_overall_deadline_remains_timeout_error(self):
        endpoint = Endpoint(); endpoint.pending = asyncio.Event()
        with self.assertRaises(TimeoutError):
            await request('http://host-a.invalid/mcp', operation='call', name='inventory',
                          http_client_factory=endpoint.client, timeout=0.05)
        self.assertEqual(1, endpoint.calls.count('tools/call'))

    async def test_mixed_expected_and_programming_group_is_not_normalized(self):
        def broken_factory(**kwargs):
            incoming = httpx.Request('POST', 'http://host-a.invalid/mcp')
            remote = httpx.HTTPStatusError('denied', request=incoming, response=httpx.Response(403, request=incoming))
            raise ExceptionGroup('synthetic mixed failure', [remote, TypeError('synthetic bug')])
        with self.assertRaises(ExceptionGroup) as caught:
            await request('http://host-a.invalid/mcp', operation='list', http_client_factory=broken_factory, timeout=2)
        def leaves(value):
            return sum((leaves(x) for x in value.exceptions), []) if isinstance(value, BaseExceptionGroup) else [value]
        self.assertTrue(any(isinstance(x, TypeError) for x in leaves(caught.exception)))
        self.assertFalse(any(isinstance(x, MCPClientError) for x in leaves(caught.exception)))


if __name__ == '__main__':
    unittest.main()
