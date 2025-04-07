const ipv4 = {
  factory: Uint8Array,
  normalize(address) {
    return address;
  },
  separator: ".",
  bitLength: 32,
  byteLength: 4,
  segments: 4,
  segmentLength: 8,
  segmentMask: 0xffn,
  mask: 0xffffffffn,
  base: 10
};

const ipv6 = {
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
  byteLength: 8,
  segments: 8,
  segmentLength: 16,
  segmentMask: 0xffffn,
  mask: 0xffffffffffffffffffffffffffffffffn,
  base: 16
};

export function IPV4(...args) {
  return _create(ipv4, ...args);
}

export function IPV6(...args) {
  return _create(ipv6, ...args);
}

function _create(definition, ...args) {
  if (args.length === 1) {
    return _encode(definition, args[0]);
  }
  return new definition.factory(args);
}

export function encodeIP(address) {
  const d = _definition(address);
  return d && _encode(d, address);
}

export function encodeIPv6(address) {
  return _encode(ipv6, address);
}

export function encodeIPv4(address) {
  return _encode(ipv4, address);
}

export function _encode(definition, address) {
  switch (typeof address) {
    case "string":
      const res = new definition.factory(definition.segments);

      let i = 0;
      for (const segment of definition
        .normalize(address)
        .split(definition.separator)) {
        res[i++] = parseInt(segment, definition.base);
      }

      return res;

    case "bigint":
      return _encodeBigInt(definition, address);

    case "object":
      if (
        address instanceof definition.factory &&
        address.length === definition.byteLength
      ) {
        return address;
      }
  }
}

function _decode(definition, address, length) {
  switch (typeof address) {
    case "string":
      if (length === undefined) {
        return address;
      }
      address = _encode(definition, address);
      break;
    case "bigint":
      address = _encodeBigInt(definition, address);
  }

  let result = "";
  let compressed = 0;
  let word;
  let last = address?.length;

  if (length !== undefined) {
    length /= definition.segmentLength;

    if (length < last) {
      last = length;
    }
  }
  for (let i = 0, j = 0; i < last; j = j + 1, i = j) {
    for (; j < last; j++) {
      word = address[j];

      if (word !== 0 || !definition.compressor || compressed > 0) {
        break;
      }
    }

    if (j > i + 1) {
      compressed++;
      result += definition.compressor;
    } else {
      if (result.length > 0) {
        result += definition.separator;
      }
    }

    if (j < last) {
      result += word.toString(definition.base);
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

function _definition(address) {
  for (const defintion of [ipv4, ipv6]) {
    if (_is(defintion, address)) {
      return defintion;
    }
  }
}

export function _is(definition, address) {
  switch (typeof address) {
    case "string":
      return address.indexOf(definition.separator) >= 0;

    case "object":
      return (
        address instanceof definition.factory &&
        address.length === definition.byteLength
      );
  }

  return false;
}

export function asBigInt(address) {
  return _asBigInt(isIPv4(address) ? ipv4 : ipv6, address);
}

function _asBigInt(definition, address) {
  if (typeof address === "bigint") {
    return address;
  }

  const ea = _encode(definition, address);

  let result = 0n;

  for (let i = 0; i < ea.length; i++) {
    result = result << BigInt(definition.segmentLength);
    result += BigInt(ea[i]);
  }

  return result;
}

function _encodeBigInt(definition, address) {
  const segments = [];

  for (let i = 0; i < definition.segments; i++) {
    segments.push(Number(address & definition.segmentMask));
    address >>= BigInt(definition.segmentLength);
  }

  return new definition.factory(segments.reverse());
}

export function prefixIP(address, length) {
  const definition = isIPv4(address) ? ipv4 : ipv6;
  return _decode(definition, _prefix(definition, address, length));
}

export function _prefix(definition, address, length) {
  return (
    _asBigInt(definition, address) &
    (definition.mask << BigInt(definition.bitLength - length))
  );
}

export function rangeIP(address, prefix, lowerAdd = 0, upperReduce = 0) {
  const definition = isIPv4(address) ? ipv4 : ipv6;

  const from = _prefix(definition, address, prefix);
  const to = from | ((1n << BigInt(definition.bitLength - prefix)) - 1n);

  return [_encode(definition, from + BigInt(lowerAdd)), _encode(definition, to - BigInt(upperReduce))];
}

export function normalizeCIDR(address) {
  let [prefix, prefixLength] = address.split(/\//);
  let longPrefix;

  if (!prefixLength && isLinkLocal(address)) {
    prefix = "fe80::";
    longPrefix = prefix;
    prefixLength = 64;
  } else {
    prefixLength = parseInt(prefixLength);

    const definition = isIPv6(prefix) ? ipv6 : ipv4;
    let n;

    if (prefixLength) {
      n = _prefix(definition, prefix, prefixLength);
    } else {
      n = _encode(definition, prefix);

      if (isLocalhost(n)) {
        prefixLength = definition === ipv6 ? 128 : 8;
      } else {
        return {};
      }
    }
    prefix = _decode(definition, n, prefixLength);
    longPrefix = _decode(definition, n);
  }

  return {
    longPrefix,
    prefix,
    prefixLength,
    cidr: `${prefix}/${prefixLength}`
  };
}

export function formatCIDR(address, subnet) {
  return subnet ? `${address}/${subnet.prefixLength}` : address;
}

export function normalizeIP(address) {
  return decodeIP(encodeIP(address));
}

export function reverseArpa(address) {
  if (isIPv6(address)) {
    const ea = encodeIPv6(address);
    let result = [];
    for (let i = 0; i < ea.length; i++) {
      const v = ea[i];
      for (let i = 0; i < 4; i++) {
        result.push(((v >> (12 - 4 * i)) & 0x000f).toString(16));
      }
    }
    return result.reverse().join(".") + ".ip6.arpa";
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

export function hasWellKnownSubnet(address) {
  return isLocalhost(address) || isLinkLocal(address);
}

export const IPV6_LINK_LOCAL_BROADCAST = _encode(ipv6, "ff02::1");
export const IPV6_ROUTER_BROADCAST = _encode(ipv6, "ff02::2");
export const IPV4_LOCALHOST = _encode(ipv4, "127.0.0.1");
export const IPV6_LOCALHOST = _encode(ipv6, "::1");
