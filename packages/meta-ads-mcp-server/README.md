# OpenAgent Meta Ads MCP server

This package is a pinned, independently runnable distribution of
[`hashcott/meta-ads-mcp-server`](https://github.com/hashcott/meta-ads-mcp-server)
1.5.1. It preserves that server's 54 tools and adds
`meta_ads_upload_ad_video`, bringing the write-enabled catalog to 55 tools.

The added tool accepts a public HTTP(S) video URL. Google Drive sharing URLs
are converted to the direct download endpoint before Meta fetches them. The
file must be publicly accessible. The returned `video_id` can be passed to
`meta_ads_create_ad_creative` after `meta_ads_get_ad_video` reports that Meta
has finished processing it.

Run with write tools enabled:

```sh
META_ADS_ACCESS_TOKEN=... META_ADS_ENABLE_WRITE_TOOLS=true \
  meta-ads-mcp
```

This package remains an external MCP capability. Installing it does not enable
the MCP module or register it in any OpenAgent runtime.
