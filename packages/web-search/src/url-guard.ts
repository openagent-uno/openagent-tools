/**
 * Outbound URL guard for content extraction.
 *
 * `get-single-web-page-content` fetches whatever URL the model hands it, and
 * `full-web-search` fetches whatever a results page links to. Without a guard
 * that is a server-side request forgery primitive: the extractor runs inside
 * the agent's host, so `http://169.254.169.254/latest/meta-data/`, a
 * Kubernetes service on `10.x`, the agent's own loopback gateway or a Tailscale
 * peer on `100.64/10` are all one tool call away, and the extracted text goes
 * straight back to the caller.
 *
 * The guard therefore allows only http/https and refuses any destination that
 * is not a public unicast address. The check happens twice for every
 * connection the HTTP client makes:
 *
 *   1. `assertPublicHttpUrl` before the request — rejects the scheme, an IP
 *      literal, or a hostname any of whose addresses is non-public;
 *   2. `guardedLookup` as the socket's DNS lookup — the connection is made to
 *      the very addresses that were just checked, so a name that resolves to a
 *      public address for the pre-check and to a private one for the connect
 *      (DNS rebinding) is refused instead of followed.
 *
 * Redirects are never followed by the HTTP client: each hop is re-validated by
 * `fetchPublicPage` before it is requested.
 */
import { lookup as dnsLookup } from 'node:dns/promises';
import type { LookupAddress } from 'node:dns';
import { isIP } from 'node:net';
import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';

export class BlockedUrlError extends Error {
  readonly url: string;

  constructor(url: string, reason: string) {
    super(`Refusing to fetch ${url}: ${reason}`);
    this.name = 'BlockedUrlError';
    this.url = url;
  }
}

/** Resolves a hostname to every address it has (A and AAAA). */
export type HostResolver = (hostname: string) => Promise<LookupAddress[]>;

export interface UrlGuardOptions {
  /** DNS resolver; defaults to the system resolver. Injected by tests. */
  resolve?: HostResolver;
  /** Address classifier; defaults to `isNonPublicAddress`. Injected by tests. */
  isBlockedAddress?: (address: string) => boolean;
}

export const MAX_REDIRECTS = 5;

const systemResolver: HostResolver = (hostname) => dnsLookup(hostname, { all: true, verbatim: true });

// [network, prefix length]. Everything that is not globally routable unicast.
const BLOCKED_IPV4: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT, also every Tailscale address
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, cloud metadata (169.254.169.254)
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, limited broadcast
];

const BLOCKED_IPV6: ReadonlyArray<readonly [string, number]> = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['64:ff9b:1::', 48], // local-use NAT64
  ['100::', 64], // discard-only
  ['2001::', 32], // Teredo (embeds an obfuscated IPv4 address)
  ['2001:db8::', 32], // documentation
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['fec0::', 10], // deprecated site-local
  ['ff00::', 8], // multicast
];

// IPv6 ranges whose low or middle bits carry an IPv4 address: the embedded
// address is what the packet effectively reaches, so it is checked as IPv4.
// [network, prefix length, byte offset of the embedded IPv4 address]
const IPV4_EMBEDDING_IPV6: ReadonlyArray<readonly [string, number, number]> = [
  ['::ffff:0:0', 96, 12], // IPv4-mapped
  ['::', 96, 12], // IPv4-compatible (deprecated)
  ['64:ff9b::', 96, 12], // well-known NAT64
  ['2002::', 16, 2], // 6to4
];

function parseIPv4(text: string): number[] | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const bytes = parts.map((part) => (/^\d{1,3}$/.test(part) ? Number(part) : NaN));
  return bytes.every((b) => b >= 0 && b <= 255) ? bytes : null;
}

function parseIPv6(text: string): number[] | null {
  let address = text.toLowerCase();
  const zone = address.indexOf('%');
  if (zone !== -1) address = address.slice(0, zone);

  let tail: number[] = [];
  const lastColon = address.lastIndexOf(':');
  if (address.slice(lastColon + 1).includes('.')) {
    const v4 = parseIPv4(address.slice(lastColon + 1));
    if (!v4) return null;
    tail = v4;
    address = `${address.slice(0, lastColon + 1)}0:0`;
  }

  const halves = address.split('::');
  if (halves.length > 2) return null;
  const toGroups = (part: string) => (part === '' ? [] : part.split(':'));
  const head = toGroups(halves[0]);
  const rest = halves.length === 2 ? toGroups(halves[1]) : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...rest];

  const bytes: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    const value = parseInt(group, 16);
    bytes.push(value >> 8, value & 0xff);
  }
  if (tail.length) bytes.splice(12, 4, ...tail);
  return bytes;
}

function inNetwork(bytes: number[], network: number[], prefix: number): boolean {
  for (let bit = 0; bit < prefix; bit++) {
    const mask = 0x80 >> (bit % 8);
    if ((bytes[bit >> 3] & mask) !== (network[bit >> 3] & mask)) return false;
  }
  return true;
}

const parsedV4 = BLOCKED_IPV4.map(([net, prefix]) => [parseIPv4(net) as number[], prefix] as const);
const parsedV6 = BLOCKED_IPV6.map(([net, prefix]) => [parseIPv6(net) as number[], prefix] as const);
const parsedEmbedding = IPV4_EMBEDDING_IPV6.map(
  ([net, prefix, offset]) => [parseIPv6(net) as number[], prefix, offset] as const,
);

function ipv4IsNonPublic(bytes: number[]): boolean {
  return parsedV4.some(([network, prefix]) => inNetwork(bytes, network, prefix));
}

/**
 * True when *address* (an IP literal, IPv6 optionally with a zone) is not a
 * public unicast address. Anything unparseable counts as non-public: the guard
 * fails closed.
 */
export function isNonPublicAddress(address: string): boolean {
  const family = isIP(address.split('%')[0]);
  if (family === 4) {
    const bytes = parseIPv4(address);
    return bytes === null || ipv4IsNonPublic(bytes);
  }
  if (family === 6) {
    const bytes = parseIPv6(address);
    if (bytes === null) return true;
    for (const [network, prefix, offset] of parsedEmbedding) {
      if (inNetwork(bytes, network, prefix) && ipv4IsNonPublic(bytes.slice(offset, offset + 4))) return true;
    }
    return parsedV6.some(([network, prefix]) => inNetwork(bytes, network, prefix));
  }
  return true;
}

function hostOf(url: URL): string {
  // WHATWG URL keeps IPv6 literals bracketed and already normalises decimal,
  // octal and hex IPv4 spellings ("2130706433", "0x7f.1") to dotted quads.
  return url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
}

async function resolvePublicAddresses(
  hostname: string,
  shownUrl: string,
  options: UrlGuardOptions,
): Promise<LookupAddress[]> {
  const isBlocked = options.isBlockedAddress ?? isNonPublicAddress;
  if (isIP(hostname)) {
    if (isBlocked(hostname)) {
      throw new BlockedUrlError(shownUrl, `${hostname} is not a public address`);
    }
    return [{ address: hostname, family: isIP(hostname) }];
  }
  const addresses = await (options.resolve ?? systemResolver)(hostname);
  if (addresses.length === 0) {
    throw new BlockedUrlError(shownUrl, `${hostname} did not resolve to any address`);
  }
  const blocked = addresses.find((entry) => isBlocked(entry.address));
  if (blocked) {
    throw new BlockedUrlError(shownUrl, `${hostname} resolves to ${blocked.address}, which is not a public address`);
  }
  return addresses;
}

/** Parse *rawUrl* and require http(s) to a public destination. */
export async function assertPublicHttpUrl(rawUrl: string, options: UrlGuardOptions = {}): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new BlockedUrlError(rawUrl, 'not a valid absolute URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new BlockedUrlError(rawUrl, `scheme ${url.protocol} is not http or https`);
  }
  await resolvePublicAddresses(hostOf(url), rawUrl, options);
  return url;
}

/**
 * An axios `lookup` that only ever hands the socket addresses that passed the
 * guard — the connection is pinned to them. Axios adapts an async lookup to
 * Node's callback form, including the `all: true` that happy-eyeballs uses.
 */
export function guardedLookup(options: UrlGuardOptions = {}) {
  return async (hostname: string, lookupOptions: object): Promise<[Array<{ address: string; family: 4 | 6 }>]> => {
    const addresses = await resolvePublicAddresses(hostname, hostname, options);
    const wanted = Number((lookupOptions as { family?: unknown }).family) || 0;
    const usable = wanted ? addresses.filter((entry) => entry.family === wanted) : addresses;
    if (usable.length === 0) {
      const error: NodeJS.ErrnoException = new Error(`${hostname} has no IPv${wanted} address`);
      error.code = 'ENOTFOUND';
      throw error;
    }
    return [usable.map((entry) => ({ address: entry.address, family: entry.family === 6 ? 6 : 4 }))];
  };
}

/**
 * GET *rawUrl* with axios, re-validating every redirect hop.
 *
 * `config` must not try to follow redirects or route through a proxy: a proxy
 * resolves the target itself, which would defeat the pinned lookup.
 */
export async function fetchPublicPage(
  rawUrl: string,
  config: AxiosRequestConfig,
  options: UrlGuardOptions = {},
): Promise<AxiosResponse> {
  let current = await assertPublicHttpUrl(rawUrl, options);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let response: AxiosResponse;
    try {
      response = await axios.get(current.href, {
        ...config,
        maxRedirects: 0,
        proxy: false,
        lookup: guardedLookup(options),
      });
    } catch (error) {
      // A refusal from the pinned lookup arrives wrapped in an AxiosError;
      // surface it as the guard decision it is, like the pre-check's.
      if (axios.isAxiosError(error) && error.cause instanceof BlockedUrlError) {
        throw error.cause;
      }
      throw error;
    }
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.location;
    if (typeof location !== 'string' || location === '') {
      throw new Error(`Redirect ${response.status} from ${current.href} has no Location header`);
    }
    current = await assertPublicHttpUrl(new URL(location, current).href, options);
  }
  throw new Error(`Too many redirects (more than ${MAX_REDIRECTS}) starting at ${rawUrl}`);
}
