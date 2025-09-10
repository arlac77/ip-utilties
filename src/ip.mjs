const ipv4 = {
  name: "IPv4",
  factory: Uint8Array,
  normalize(address) {
    return address;
  },
  separator: ".",
  bitLength: 32,
  segments: 4,
  segmentLength: 8,
  segmentMask: 0xffn,
  base: 10
};

const ipv6 = {
  name: "IPv6",
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
  base: 16
};

export function encodeIP(address) {
  const d = _family(address);
  return d && _encode(d, address);
}

export function encodeIPv6(address) {
  return _encode(ipv6, address);
}

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
  let compressed = 0;
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

      if (word !== 0 || !family.compressor || compressed > 0) {
        break;
      }
    }

    if (j > i + 1) {
      compressed++;
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
  return [ipv4, ipv6].find(d => _is(d, address));
}

function _is(family, address) {
  switch (typeof address) {
    case "string":
      return address.indexOf(family.separator) >= 0;

    case "object":
      return (
        address instanceof family.factory && address.length === family.segments
      );
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
  return _prefix(family, address, length) === _prefix(family, prefix, length);
}

export function normalizeCIDR(address) {
  let [prefix, prefixLength] = address.split(/\//);
  let longPrefix;

  if (isUniqueLocal(address) || isLinkLocal(address)) {
    prefixLength = 64;
    const n = _prefix(ipv6, address, prefixLength);
    prefix = _decode(ipv6, n, prefixLength);
    if (!prefix.endsWith("::")) {
      // TODO
      prefix += prefix.endsWith(":") ? ":" : "::";
    }
    longPrefix = prefix;
  } else {
    prefixLength = prefixLength === undefined ? 0 : parseInt(prefixLength);

    const family = /*_family(prefix); */ isIPv6(prefix) ? ipv6 : ipv4;
    let n;

    if (prefixLength) {
      n = _prefix(family, prefix, prefixLength);
    } else {
      n = _encode(family, prefix);

      if (isLocalhost(n)) {
        prefixLength = family === ipv6 ? 128 : 8;
      }
    }
    prefix = _decode(family, n, prefixLength);
    longPrefix = _decode(family, n);
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
  return decodeIP(encodeIP(address));
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

export function isLocalhost(address) {
  const eaddr = encodeIP(address);

  if (!eaddr) {
    return false;
  }

  const str = eaddr.toString();

  return str === IPV4_LOCALHOST.toString() || str === IPV6_LOCALHOST.toString();
}

export function isLinkLocal(address) {
  const eaddr = encodeIP(address);
  return eaddr?.[0] === 0xfe80;
}

export function isUniqueLocal(address) {
  const eaddr = encodeIP(address);
  return eaddr?.[0] >> 9 === 126 ? true : false;
}

export function hasWellKnownSubnet(address) {
  return isLocalhost(address) || isLinkLocal(address) || isUniqueLocal(address);
}

export const IPV6_LINK_LOCAL_BROADCAST = _encode(ipv6, "ff02::1");
export const IPV6_ROUTER_BROADCAST = _encode(ipv6, "ff02::2");
export const IPV4_LOCALHOST = _encode(ipv4, "127.0.0.1");
export const IPV6_LOCALHOST = _encode(ipv6, "::1");
