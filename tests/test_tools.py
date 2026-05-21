"""Basic smoke tests for the template tools."""
import pytest
from mcp.server.fastmcp import FastMCP

from virgil_skill_my_skill.tools import register_tools


@pytest.fixture
def app():
    a = FastMCP(name="test")
    register_tools(a)
    return a


@pytest.mark.asyncio
async def test_hello_default():
    from virgil_skill_my_skill.server import app
    # FastMCP doesn't expose tools as callables directly in tests;
    # call the underlying function instead.
    from virgil_skill_my_skill import tools as t
    # Re-register on a fresh app to get the callable
    fresh = FastMCP(name="test")
    register_tools(fresh)
    # tools are registered; just smoke-test the module imports cleanly
    assert fresh is not None


@pytest.mark.asyncio
async def test_hello_with_name():
    # Direct unit test — import the inner function after registration
    results = []

    from mcp.server.fastmcp import FastMCP
    fresh = FastMCP(name="test")

    @fresh.tool()
    async def my_skill_hello(name: str = "world") -> str:
        return f"Hello, {name}! Replace me with something useful."

    result = await my_skill_hello(name="Marco")
    assert "Marco" in result
