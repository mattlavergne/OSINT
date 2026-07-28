/**
 * Bootstrap prefix matching.
 *
 * RFC 7484 bootstrap entries are keyed by CIDR, and IPv6 prefixes are routinely
 * shorter than a single hextet (2000::/3, 2600::/12). An earlier version
 * compared whole hextets, which made every service "match" and silently routed
 * IPv6 lookups to an arbitrary registry. These pin the numeric comparison.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { inPrefix } from '../src/lib/rdap.js';

describe('RDAP bootstrap prefix matching', () => {
  test('matches IPv4 ranges on the mask, not the octet', () => {
    assert.equal(inPrefix('8.8.8.8', '8.0.0.0', 9, false), true);
    assert.equal(inPrefix('8.128.0.1', '8.0.0.0', 9, false), false);
    assert.equal(inPrefix('140.82.114.3', '140.0.0.0', 8, false), true);
    assert.equal(inPrefix('192.168.1.1', '10.0.0.0', 8, false), false);
  });

  test('handles the IPv4 edge lengths', () => {
    assert.equal(inPrefix('1.2.3.4', '0.0.0.0', 0, false), true);
    assert.equal(inPrefix('1.2.3.4', '1.2.3.4', 32, false), true);
    assert.equal(inPrefix('1.2.3.5', '1.2.3.4', 32, false), false);
  });

  test('matches IPv6 prefixes shorter than one hextet', () => {
    // The case that was broken: /3 and /12 cannot be compared hextet-wise.
    assert.equal(inPrefix('2606:4700:4700::1111', '2000::', 3, true), true);
    assert.equal(inPrefix('2606:4700:4700::1111', '2600::', 12, true), true);
    assert.equal(inPrefix('2606:4700:4700::1111', '2800::', 12, true), false);
    assert.equal(inPrefix('2a00:1450::1', '2a00::', 12, true), true);
    assert.equal(inPrefix('2a00:1450::1', '2600::', 12, true), false);
  });

  test('handles compressed and full IPv6 forms alike', () => {
    assert.equal(inPrefix('2606:4700::1', '2606:4700::', 32, true), true);
    assert.equal(inPrefix('2606:4700:0000:0000:0000:0000:0000:0001', '2606:4700::', 32, true), true);
    assert.equal(inPrefix('2606:4701::1', '2606:4700::', 32, true), false);
    assert.equal(inPrefix('::1', '::', 0, true), true);
  });
});
