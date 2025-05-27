import test from "ava";
import {
  hasWellKnownSubnet,
  isLocalhost,
  isLinkLocal,
  isUniqueLocal,
  isIPv4,
  isIPv6,
  encodeIP,
  encodeIPv4,
  encodeIPv6,
  decodeIP,
  decodeIPv4,
  decodeIPv6,
  asBigInt,
  normalizeIP,
  prefixIP,
  normalizeCIDR,
  formatCIDR,
  familyIP,
  rangeIP,
  reverseArpa,
  matchPrefixIP,
  IPV4_LOCALHOST,
  IPV6_LOCALHOST
} from "../src/ip.mjs";

test("IPV4_LOCALHOST", t =>
  t.deepEqual(IPV4_LOCALHOST, new Uint8Array([127, 0, 0, 1])));
test("IPV6_LOCALHOST", t =>
  t.deepEqual(IPV6_LOCALHOST, new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1])));

function isIPv4T(t, address, expected) {
  t.is(isIPv4(address), expected);
}
isIPv4T.title = (providedTitle = "isIPv4", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

function isIPv6T(t, address, expected) {
  t.is(isIPv6(address), expected);
}
isIPv6T.title = (providedTitle = "isIPv6", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(isIPv4T, IPV4_LOCALHOST, true);
test("Uint8Array 127.0.0.1", isIPv4T, new Uint8Array([127, 0, 0, 1]), true);
test("Uint8Array 127.0.0.1", isIPv6T, new Uint8Array([127, 0, 0, 1]), false);

test(isIPv6T, IPV4_LOCALHOST, false);

test(isIPv4T, IPV6_LOCALHOST, false);
test(isIPv6T, IPV6_LOCALHOST, true);
test(
  "Uint16Array ::1",
  isIPv4T,
  new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1]),
  false
);
test(
  "Uint16Array ::1",
  isIPv6T,
  new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1]),
  true
);

test(isIPv4T, "1.2.3.4", true);
test(isIPv4T, new Uint8Array([1, 2, 3, 4]), true);
test.failing(isIPv4T, "1.2.3", false);
test(isIPv4T, new Uint8Array([1, 2, 3]), false);
test(isIPv4T, "f:b:a:3::", false);
test(isIPv6T, "f:b:a:3::", true);
test.failing(isIPv6T, "f:b:a:3:0:0", false);

function isLocalhostT(t, address, expected) {
  t.is(isLocalhost(address), expected);
}
isLocalhostT.title = (providedTitle = "isLocalhost", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(isLocalhostT, IPV6_LOCALHOST, true);
test(isLocalhostT, IPV4_LOCALHOST, true);
test(isLocalhostT, "1.2.3.4", false);
test(isLocalhostT, "1::2:3", false);
test(isLocalhostT, "127.0.0.1", true);
test(isLocalhostT, "::1", true);
test(isLocalhostT, "::1%lo", true);
test(isLocalhostT, "::1/127", true);
test(isLocalhostT, "", false);
test(isLocalhostT, 2, false);
test(isLocalhostT, 3.14, false);
test(isLocalhostT, 4n, false);
test(isLocalhostT, false, false);
test(isLocalhostT, true, false);
test(isLocalhostT, undefined, false);
test(isLocalhostT, null, false);
test(isLocalhostT, {}, false);

function isLinkLocalT(t, address, expected) {
  t.is(isLinkLocal(address), expected);
}
isLinkLocalT.title = (providedTitle = "isLinkLocal", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(isLinkLocalT, "1.2.3.4", false);
test(isLinkLocalT, "fe80:0000:0000:0000:1e57:3eff:fe22:9a8f/64", true);
test(isLinkLocalT, "fe80:::1e57:3eff:fe22:9a8f/64", true);
test(isLinkLocalT, "fe80:::1e57:3eff:fe22:9a8f", true);
test(
  isLinkLocalT,
  new Uint16Array([0xfe80, 0, 0, 0, 0x1e57, 0x3eff, 0xfe22, 0x9a8f]),
  true
);
test(isLinkLocalT, "", false);
test(isLinkLocalT, 2, false);
test(isLinkLocalT, 3.14, false);
test(isLinkLocalT, 4n, false);
test(isLinkLocalT, false, false);
test(isLinkLocalT, true, false);
test(isLinkLocalT, undefined, false);
test(isLinkLocalT, null, false);
test(isLinkLocalT, {}, false);

function isUniqueLocalT(t, address, expected) {
  t.is(isUniqueLocal(address), expected);
}
isUniqueLocalT.title = (providedTitle = "isUniqueLocal", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(isUniqueLocalT, "1.2.3.4", false);
test(isUniqueLocalT, "fe80::1e57:3eff:fe22:9a8f/64", false);
test(isUniqueLocalT, "fc00::1", true);

test(isUniqueLocalT, "", false);
test(isUniqueLocalT, 2, false);
test(isUniqueLocalT, 3.14, false);
test(isUniqueLocalT, 4n, false);
test(isUniqueLocalT, false, false);
test(isUniqueLocalT, true, false);
test(isUniqueLocalT, undefined, false);
test(isUniqueLocalT, null, false);
test(isUniqueLocalT, {}, false);

function encodeIPT(t, address, expected) {
  t.deepEqual(encodeIP(address), expected);
}
encodeIPT.title = (providedTitle = "encodeIP", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(encodeIPT, "1.2.3.4", new Uint8Array([1, 2, 3, 4]));
test(encodeIPT, "::1", new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1]));
test(encodeIPT, "::1%lo", new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1]));
test(encodeIPT, "fe80::/64", new Uint16Array([0xfe80, 0, 0, 0, 0, 0, 0, 0]));
test(encodeIPT, "", undefined);
test(encodeIPT, undefined, undefined);
test(encodeIPT, null, undefined);
test(encodeIPT, 1, undefined);
test(encodeIPT, 2.1, undefined);
test(encodeIPT, 3n, undefined);
test(encodeIPT, true, undefined);
test(encodeIPT, false, undefined);
test(encodeIPT, {}, undefined);
test(encodeIPT, new Uint8Array([1, 2, 3, 4]), new Uint8Array([1, 2, 3, 4]));
test(
  encodeIPT,
  new Uint16Array([0xfe80, 0, 0, 0, 0, 0, 0, 0]),
  new Uint16Array([0xfe80, 0, 0, 0, 0, 0, 0, 0])
);

function encodeIPv4T(t, address, expected) {
  t.deepEqual(encodeIPv4(address), expected);
}
encodeIPv4T.title = (providedTitle = "encodeIPv4", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(encodeIPv4T, "1.2.3.4", new Uint8Array([1, 2, 3, 4]));
test(encodeIPv4T, "", new Uint8Array([0, 0, 0, 0]));

function encodeIPv6T(t, address, expected) {
  t.deepEqual(encodeIPv6(address), expected);
}
encodeIPv6T.title = (providedTitle = "encodeIPv6", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(encodeIPv6T, "::1", new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1]));
test(encodeIPv6T, "::1:1", new Uint16Array([0, 0, 0, 0, 0, 0, 1, 1]));
test(encodeIPv6T, "1::", new Uint16Array([1, 0, 0, 0, 0, 0, 0, 0]));
test(encodeIPv6T, "", new Uint16Array([0, 0, 0, 0, 0, 0, 0, 0]));

function decodeIPT(t, address, length, expected) {
  t.is(decodeIP(address, length), expected);
}
decodeIPT.title = (providedTitle = "decodeIP", address, length, expected) =>
  `${providedTitle} ${address}${
    length === undefined ? "" : "/" + length
  } => ${expected}`.trim();

test(decodeIPT, new Uint8Array([1, 2, 3, 4]), undefined, "1.2.3.4");
test(
  decodeIPT,
  new Uint16Array([0, 0, 0, 0, 0, 0xc, 0xb, 0xa]),
  undefined,
  "::c:b:a"
);

test(decodeIPT, 3n, undefined, "::3");

test(decodeIPT, undefined, undefined, "");
test(decodeIPT, null, undefined, "");
test(decodeIPT, 1, undefined, "");
test(decodeIPT, 2.1, undefined, "");
test(decodeIPT, true, undefined, "");
test(decodeIPT, false, undefined, "");
test(decodeIPT, {}, undefined, "");
test(decodeIPT, [], undefined, "");

test(decodeIPT, "1.2.3.4", undefined, "1.2.3.4");
test(decodeIPT, "1.2.3.4", 1, "1");
test(decodeIPT, "1.2.3.4", 7, "1");
test(decodeIPT, "1.2.3.4", 9, "1.2");
test(decodeIPT, "1.2.3.4", 32, "1.2.3.4");
test(decodeIPT, "::c:b:a", undefined, "::c:b:a");

function decodeIPv4T(t, address, expected) {
  t.is(decodeIPv4(address), expected);
}
decodeIPv4T.title = (providedTitle = "decodeIPv4", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(decodeIPv4T, new Uint8Array([1, 2, 3, 4]), "1.2.3.4");

function decodeIPv6T(t, address, expected) {
  t.is(decodeIPv6(address), expected);
}
decodeIPv6T.title = (providedTitle = "decodeIPv6", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(decodeIPv6T, new Uint16Array([0xfe80, 0, 0, 0, 0, 0, 0, 0]), "fe80::");
test(
  decodeIPv6T,
  new Uint16Array([0x2001, 0xdb8, 0, 0, 1, 0, 0, 1]),
  "2001:db8::1:0:0:1"
);
test(
  decodeIPv6T,
  new Uint16Array([0, 0, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa]),
  "::f:e:d:c:b:a"
);
test(
  decodeIPv6T,
  new Uint16Array([0, 0, 0xf, 0xe, 0, 0xc, 0xb, 0xa]),
  "::f:e:0:c:b:a"
);
test(
  decodeIPv6T,
  new Uint16Array([0, 0, 0, 0, 0xd, 0xc, 0xb, 0xa]),
  "::d:c:b:a"
);
test(decodeIPv6T, new Uint16Array([0, 0, 0, 0, 0, 0xc, 0xb, 0xa]), "::c:b:a");
test(decodeIPv6T, new Uint16Array([0, 0, 0, 0, 0, 0, 0, 0x000a]), "::a");

test(decodeIPv6T, 0x000an, "::a");

function normalizeIP_T(t, address, expected) {
  t.is(normalizeIP(address), expected);
}
normalizeIP_T.title = (providedTitle = "normalizeIP", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(normalizeIP_T, "0000::a", "::a");
test(normalizeIP_T, "1.2.3.04", "1.2.3.4");

function reverseArpaT(t, address, expected) {
  t.is(reverseArpa(address), expected);
}
reverseArpaT.title = (providedTitle = "reverseArpa", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(
  reverseArpaT,
  "fe80::",
  "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa"
);

test(
  reverseArpaT,
  "fd00:1:1:1::",
  "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.1.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa"
);

test(
  reverseArpaT,
  "::2",
  "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
);
test(reverseArpaT, "1.2.3.4", "4.3.2.1.in-addr.arpa");

function normalizeIPT(t, address, expected) {
  t.is(normalizeIP(address), expected);
}
normalizeIPT.title = (providedTitle = "normalizeIP", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test("wellKnownSubnet", t => {
  t.true(hasWellKnownSubnet("::1"));
  t.true(hasWellKnownSubnet("127.0.0.1"));
  t.true(hasWellKnownSubnet("fe80::1e57:3eff:fe22:9a8f"));
  t.true(hasWellKnownSubnet("fd00::1"));
  t.false(hasWellKnownSubnet("1.2.3.4"));
});

function asBigIntT(t, address, expected) {
  t.is(asBigInt(address), expected);
}
asBigIntT.title = (providedTitle = "asBigInt", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(asBigIntT, "0.0.0.1", 1n);
test(asBigIntT, "fe80::", 0xfe800000000000000000000000000000n);
test(asBigIntT, "2001:db8::1:0:0:1", 0x20010db8000000000001000000000001n);
test(asBigIntT, "::f:e:d:c:b:a", 0xf000e000d000c000b000an);
test(asBigIntT, "::f:e:0:c:b:a", 0xf000e0000000c000b000an);
test(asBigIntT, "::d:c:b:a", 0xd000c000b000an);
test(asBigIntT, "::c:b:a", 0xc000b000an);
test(asBigIntT, "::a", 0x000an);
test(asBigIntT, 2n, 2n);

function prefixIPT(t, address, length, expected) {
  t.is(prefixIP(address, length), expected);
}
prefixIPT.title = (providedTitle = "prefixIP", address, length, expected) =>
  `${providedTitle} ${address}/${length} => ${expected}`.trim();

test(prefixIPT, "1.2.3.4", 0, "0.0.0.0");
test(prefixIPT, "1.2.3.4", 8, "1.0.0.0");
test(prefixIPT, "1.2.3.4", 16, "1.2.0.0");
test(prefixIPT, "1.2.3.4", 24, "1.2.3.0");
test(prefixIPT, "1.2.3.4", 32, "1.2.3.4");

test(prefixIPT, "2001:db8::1:0:0:1", 0, "::");
test(prefixIPT, "2001:db8::1:0:0:1", 16, "2001::");
test(prefixIPT, "2001:db8::1:0:0:1", 32, "2001:db8::");
test(prefixIPT, "2001:db8::1:0:0:1", 64, "2001:db8::");
test(prefixIPT, "2001:db8::1:0:0:1", 92, "2001:db8::1:0:0:0");
test(prefixIPT, "2001:db8::1:0:0:1", 128, "2001:db8::1:0:0:1");

function normalizeCIDRT(t, address, expected) {
  const { cidr } = normalizeCIDR(address);
  t.is(cidr, expected);
}
normalizeCIDRT.title = (providedTitle = "normalizeCIDR", address, cidr) =>
  `${providedTitle} ${address} => ${cidr}`.trim();

test(normalizeCIDRT, "127/8", "127/8");
test(normalizeCIDRT, "127.0.0.1", "127/8");
test(normalizeCIDRT, "::1", "::1/128");
test(normalizeCIDRT, "1.2.3.4/24", "1.2.3/24");
test(normalizeCIDRT, "1.2.3.4/16", "1.2/16");
test(normalizeCIDRT, "10.0/16", "10.0/16");
test(normalizeCIDRT, "1.2.3.4/8", "1/8");
test(normalizeCIDRT, "192.168.1.62/30", "192.168.1.60/30");
test(normalizeCIDRT, "fe80::/64", "fe80::/64");
test(normalizeCIDRT, "fd00::", "fd00::/64");
test(normalizeCIDRT, "fd00:1:1:1::", "fd00:1:1:1/64");
test(normalizeCIDRT, "::/0", "/0");
test(normalizeCIDRT, "0.0.0.0/0", "/0");
test(normalizeCIDRT, "1.2.3.4", "/0");

function rangeIPT(t, address, prefix, l, u, expectedFrom, expectedTo) {
  const [from, to] = rangeIP(address, prefix, l, u);
  t.is(decodeIP(from), expectedFrom);
  t.is(decodeIP(to), expectedTo);
}
rangeIPT.title = (
  providedTitle = "rangeIP",
  address,
  prefix,
  l,
  u,
  expectedFrom,
  expectedTo
) =>
  `${providedTitle} ${address}/${prefix} [${l},${u}] => ${expectedFrom} - ${expectedTo}`.trim();

test(rangeIPT, "192.168.1.7", 24, 0, 0, "192.168.1.0", "192.168.1.255");
test(rangeIPT, "192.168.1.7", 24, 1, 0, "192.168.1.1", "192.168.1.255");
test(rangeIPT, "192.168.1.7", 16, 0, 0, "192.168.0.0", "192.168.255.255");
test(rangeIPT, "192.168.1.61", 30, 0, 0, "192.168.1.60", "192.168.1.63");
test(rangeIPT, "fe80::", 64, 0, 0, "fe80::", "fe80::ffff:ffff:ffff:ffff");
test(rangeIPT, "fe80::", 96, 0, 0, "fe80::", "fe80::ffff:ffff");

function formatCIDRT(t, address, prefixLength, expected) {
  t.is(formatCIDR(address, prefixLength), expected);
}
formatCIDRT.title = (
  providedTitle = "formatCIDR",
  address,
  prefixLength,
  cidr
) => `${providedTitle} ${address}/${prefixLength} => ${cidr}`.trim();

test(formatCIDRT, "192.168.1.62", 30, "192.168.1.62/30");
test(formatCIDRT, encodeIP("192.168.1.62"), 30, "192.168.1.62/30");

function familyIPT(t, address, expected) {
  t.is(familyIP(address), expected);
}
familyIPT.title = (providedTitle = "familyIP", address, expected) =>
  `${providedTitle} ${address} => ${expected}`.trim();

test(familyIPT, "1.2.3.4", "IPv4");
test(familyIPT, "::1", "IPv6");
test(familyIPT, "", undefined);
test(familyIPT, "some name", undefined);

function matchPrefixIPT(t, prefix, length, address, expected) {
  t.is(matchPrefixIP(prefix, length, address), expected);
}
matchPrefixIPT.title = (
  providedTitle = "matchPrefixIP",
  prefix,
  length,
  address,
  expected
) => `${providedTitle} ${prefix} ${length} ${address} => ${expected}`.trim();

test(matchPrefixIPT, "192.168.1.0", 24, "192.168.1.62", true);
test(matchPrefixIPT, "192.168.2.0", 24, "192.168.1.62", false);
test(matchPrefixIPT, "fe80::", 64, "fe80::c696:7f50:8c5:de0a", true);
