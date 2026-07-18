/**
 * Address familiy IPv4
 */
export const FAMILY_IPV4 = "IPv4";

/**
 * Address familiy IPv6
 */
export const FAMILY_IPV6 = "IPv6";

const ipv4 = {
  name: FAMILY_IPV4,
  factory: Uint8Array,
  normalize: address => address,
  separator: ".",
  bitLength: 32,
  segments: 4,
  segmentLength: 8,
  segmentMask: 0xffn,
  base: 10,
  localHost: new Uint8Array([127, 0, 0, 1]),
  localHostPrefixLenth: 8,

  // https://www.geeksforgeeks.org/computer-networks/subnet-cheat-sheet/
  wellKnownAddresses: [
    // mask                            length, prefix, link local,
    [new Uint8Array([169, 254, 0, 0]), /* */ 16, 16, true], // Link-local address (Autoconfiguration)

    [new Uint8Array([0, 0, 0, 0]), /*        */ 8, 8], // This network
    [new Uint8Array([10, 0, 0, 0]), /*       */ 8, 8], // Private network (RFC 1918)
    [new Uint8Array([100, 64, 0, 0]), /*    */ 10, 10], // Carrier-grade NAT / Shared address space (CGN)
    [new Uint8Array([127, 0, 0, 0]), /*      */ 8, 8], // Loopback
    [new Uint8Array([172, 16, 0, 0]), /*    */ 12, 12], // Private network (RFC 1918)
    [new Uint8Array([192, 0, 0, 0]), /*     */ 24, 24], // IETF protocol assignments
    [new Uint8Array([192, 0, 2, 0]), /*     */ 24, 24], // TEST-NET-1
    [new Uint8Array([192, 168, 0, 0]), /*   */ 16, 16], // Private network (RFC 1918)
    [new Uint8Array([198, 18, 0, 0]), /*    */ 15, 15], // Network benchmark testing
    [new Uint8Array([198, 51, 100, 0]), /*  */ 24, 24], // TEST-NET-2
    [new Uint8Array([203, 0, 113, 0]), /*   */ 24, 24], // Reserved address space used for documentation
    [new Uint8Array([240, 0, 0, 0]), /*      */ 4, 4], // Reserved for future use or experimental purposes

    [new Uint8Array([127, 0, 53, 53]), /*    */ 0, 0], // Name collision occurrence
    [new Uint8Array([255, 255, 255, 255]), /**/ 0, 0] // Limited Broadcast address
  ]
};

const ipv6 = {
  name: FAMILY_IPV6,
  factory: Uint16Array,
  normalize(address) {
    const parts = address.split(":");
    const i = parts.indexOf("");
    if (i >= 0) {
      parts.splice(i, 1, ..."0".repeat(9 - parts.length));
    }
    return parts.join(":");
  },
  separator: ":",
  compressor: "::",
  bitLength: 128,
  segments: 8,
  segmentLength: 16,
  segmentMask: 0xffffn,
  base: 16,
  localHost: new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1]),
  localHostPrefixLenth: 128,
  wellKnownAddresses: [
    [new Uint16Array([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 64, 64, true],
    [new Uint16Array([0xfd00, 0, 0, 0, 0, 0, 0, 0]), 8, 64, false, true],
    [new Uint16Array([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7, 64, false, true],
    [new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1]), 128, 128, false, true]
  ]
};

const families = [ipv4, ipv6];

/**
 * Encode ipv4 or ipv6 address into number array.
 * @param {string|number[]} address
 * @returns number[]
 */
export function encodeIP(address) {
  const d = _family(address);
  return d && _encode(d, address);
}

/**
 * Encode ipv6 address into number array.
 * @param {string|number[]|bigint} address
 * @returns number[]
 */
export function encodeIPv6(address) {
  return _encode(ipv6, address);
}

/**
 * Encode ipv4 address into number array.
 * @param {string|number[]|bigint} address
 * @returns number[]
 */
export function encodeIPv4(address) {
  return _encode(ipv4, address);
}

function _encode(family, address) {
  switch (typeof address) {
    case "string":
      const res = new family.factory(family.segments);

      let i = 0;
      for (const segment of family.normalize(address).split(family.separator)) {
        res[i++] = parseInt(segment, family.base);
      }

      return res;

    case "bigint":
      return _encodeBigInt(family, address);

    case "object":
      if (
        address instanceof family.factory &&
        address.length === family.segments
      ) {
        return address;
      }
  }
}

function _decode(family, address, length) {
  switch (typeof address) {
    case "string":
      if (length === undefined) {
        return address;
      }
      address = _encode(family, address);
      break;
    case "bigint":
      address = _encodeBigInt(family, address);
  }

  let result = "";
  let compressed = false;
  let word;
  let last = address?.length;

  if (length !== undefined) {
    length /= family.segmentLength;

    if (length < last) {
      last = length;
    }
  }
  for (let i = 0, j = 0; i < last; j = j + 1, i = j) {
    for (; j < last; j++) {
      word = address[j];

      if (word !== 0 || !family.compressor || compressed) {
        break;
      }
    }

    if (j > i + 1) {
      compressed = true;
      result += family.compressor;
    } else {
      if (result.length > 0) {
        result += family.separator;
      }
    }

    if (j < last) {
      result += word.toString(family.base);
    }
  }

  return result;
}

export function decodeIPv6(address, length) {
  return _decode(ipv6, address, length);
}

export function decodeIPv4(address, length) {
  return _decode(ipv4, address, length);
}

export function decodeIP(address, length) {
  return _decode(isIPv4(address) ? ipv4 : ipv6, address, length);
}

export function isIPv4(address) {
  return _is(ipv4, address);
}

export function isIPv6(address) {
  return _is(ipv6, address);
}

/**
 * IP address family for a given address.
 * @param {string|Uint8Array|Uint16Array} address
 * @return {string|undefined}
 */
export function familyIP(address) {
  return _family(address)?.name;
}

function _family(address) {
  return families.find(d => _is(d, address));
}

function _is(family, address) {
  switch (typeof address) {
    case "string":
      return address.indexOf(family.separator) >= 0;

    case "object":
      return (
        address instanceof family.factory && address.length === family.segments
      );

    case "bigint": {
      if (family === ipv6 && address > 1n << BigInt(ipv4.bitLength)) {
        return true;
      }
    }
  }

  return false;
}

export function asBigInt(address) {
  return _asBigInt(_family(address), address);
}

function _asBigInt(family, address) {
  if (typeof address === "bigint") {
    return address;
  }

  return _encode(family, address).reduce(
    (a, c) => (a << BigInt(family.segmentLength)) + BigInt(c),
    0n
  );
}

function _encodeBigInt(family, address) {
  const segments = [];

  for (let i = 0; i < family.segments; i++) {
    segments.push(Number(address & family.segmentMask));
    address >>= BigInt(family.segmentLength);
  }

  return new family.factory(segments.reverse());
}

export function prefixIP(address, length) {
  const family = _family(address);
  return _decode(family, _prefix(family, address, length));
}

export function prefixOnlyIP(address, length) {
  const family = _family(address);
  return _decode(family, _prefix(family, address, length), length);
}

function _prefix(family, address, length) {
  return (
    _asBigInt(family, address) & (-1n << BigInt(family.bitLength - length))
  );
}

export function rangeIP(address, prefix, lowerAdd = 0, upperReduce = 0) {
  const family = _family(address);
  const from = _prefix(family, address, prefix);
  const to = from | ((1n << BigInt(family.bitLength - prefix)) - 1n);
  return [
    _encode(family, from + BigInt(lowerAdd)),
    _encode(family, to - BigInt(upperReduce))
  ];
}

export function matchPrefixIP(prefix, length, address) {
  const family = _family(address);
  return (
    family !== undefined &&
    _prefix(family, address, length) === _prefix(family, prefix, length)
  );
}

export function normalizeCIDR(address) {
  let [prefix, prefixLength] = address.split(/\//);
  let longPrefix;

  const family = isIPv6(prefix) ? ipv6 : ipv4;
  let encoded = _encode(family, prefix);
  const wns = _wellKnownSubnet(family, encoded);

  if (wns) {
    prefixLength ||= wns[2];
    prefix = _decode(
      family,
      _prefix(family, encoded, prefixLength),
      prefixLength
    );
    longPrefix = _decode(family, wns[0]);
  } else {
    prefixLength = prefixLength === undefined ? 0 : parseInt(prefixLength);

    if (prefixLength) {
      encoded = _prefix(family, prefix, prefixLength);
    } else {
      if (_isLocalhost(family, encoded)) {
        prefixLength = family.localHostPrefixLenth;
      }
    }
    prefix = _decode(family, encoded, prefixLength);
    longPrefix = _decode(family, encoded);
  }

  return {
    longPrefix,
    prefix,
    prefixLength,
    cidr: `${prefix}/${prefixLength}`
  };
}

export function formatCIDR(address, prefixLength) {
  return prefixLength ? `${decodeIP(address)}/${prefixLength}` : address;
}

export function normalizeIP(address) {
  const f = _family(address);
  return f && _decode(f, _encode(f, address));
}

export function reverseArpa(address) {
  if (isIPv6(address)) {
    return (
      encodeIPv6(address)
        .reduce(
          (a, segment) => (a += segment.toString(16).padStart(4, "0")),
          ""
        )
        .split("")
        .reverse()
        .reduce((all, s) => {
          if (all.length > 0 || s !== "0") {
            all.push(s);
          }
          return all;
        }, [])
        .join(".") + ".ip6.arpa"
    );
  }

  return address.split(".").reverse().join(".") + ".in-addr.arpa";
}

function _equal(a, b) {
  let i = 0;
  for (const slot of a) {
    if (slot !== b[i++]) {
      return false;
    }
  }
  return true;
}

export function _isLocalhost(family, encoded) {
  return _equal(family.localHost, encoded);
}

export function isLocalhost(address) {
  const family = _family(address);
  if (family) {
    return _isLocalhost(family, _encode(family, address));
  }
  return false;
}

export function isLinkLocal(address) {
  const family = _family(address);
  if (family) {
    return _isLinkLocal(family, _encode(family, address));
  }
  return false;
}

export function _isLinkLocal(family, address) {
  return _wellKnownSubnet(family, address) === family.wellKnownAddresses[0];
}

export function isUniqueLocal(address) {
  const eaddr = encodeIP(address);
  return eaddr?.[0] >> 9 === 126 ? true : false;
}

export function _isUniqueLocal(eaddr) {
  return eaddr?.[0] >> 9 === 126 ? true : false;
}

export function hasWellKnownSubnet(address) {
  return wellKnownSubnet(address) !== undefined;
}

export function wellKnownSubnet(address) {
  const family = _family(address);
  if (family) {
    return _wellKnownSubnet(family, _encode(family, address));
  }
}

export function _wellKnownSubnet(family, encoded) {
  for (const c of family.wellKnownAddresses) {
    const pl = c[1];
    if (pl > 0 && _prefix(family, c[0], pl) === _prefix(family, encoded, pl)) {
      /*console.log(
          c,
          encoded,
          _prefix(family, c[0], pl),
          _prefix(family, encoded, pl),
          prefixIP(c[0], pl),
          prefixIP(encoded, pl)
        );*/
      return c;
    }
  }
}

/*
  prefix     global subnet interface
  ff01:: ff02::   1
  ff05::          2 3

  https://en.wikipedia.org/wiki/Link-local_address
  fe80::          64       link local
  169.254. /16             link local

  https://en.wikipedia.org/wiki/Unique_local_address
  fc00::          64       unique local
  fd00::          64       unique local

  ::1             128.     local host
  127             8        local host
  172
*/

/*
 * https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
 */
export const IPV6_NODE_LOCAL_ALL_NODES = _encode(ipv6, "ff01::1");
export const IPV6_NODE_LOCAL_ALL_ROUTERS = _encode(ipv6, "ff01::2");
export const IPV6_LINK_LOCAL_ALL_NODES = _encode(ipv6, "ff02::1");
export const IPV6_LINK_LOCAL_ALL_ROUTERS = _encode(ipv6, "ff02::2");
export const IPV6_SITE_LOCAL_ALL_ROUTERS = _encode(ipv6, "ff05::2");
export const IPV6_SITE_LOCAL_ALL_DHCP_SERVERS = _encode(ipv6, "ff05::1:3");

export const IPV4_LOCALHOST = ipv4.localHost;
export const IPV6_LOCALHOST = ipv6.localHost;
