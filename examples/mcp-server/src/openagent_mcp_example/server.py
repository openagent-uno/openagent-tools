"""Independent MCP example. The host owns registration and authorization."""
import logging
import os
from mcp.server.fastmcp import FastMCP
from .tools import register_tools

app = FastMCP('example-tools')
register_tools(app)


def main():
    logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'))
    app.run(transport='stdio')


if __name__ == '__main__':
    main()
