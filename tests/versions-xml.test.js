import test from 'node:test';
import assert from 'node:assert/strict';
import { parseGalleryDependencies, parseGalleryFeed } from '../scanner/xml.js';
import { compareVersions, isVersionAffected, parseNugetRange, versionMatchesRange } from '../scanner/versions.js';

test('PowerShell Gallery feed parses page entries and a next link', () => {
  const xml = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
    <link rel="next" href="/api/v2/Packages?$skip=1&amp;$top=1" />
    <entry><id>https://gallery.example/api/v2/Packages(Id='wrong',Version='9.9.9')</id><title>Atom title</title><content><m:properties xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
      <d:Id xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices">Example</d:Id>
      <d:Version xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices">1.2.0-beta.1</d:Version>
      <d:Title xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices">Example &amp; Tools</d:Title>
      <d:LastUpdated xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices">2026-10-01T00:00:00Z</d:LastUpdated>
      <d:IsAbsoluteLatestVersion xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices">true</d:IsAbsoluteLatestVersion>
      <d:Dependencies xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices">Core:[1.0.0,2.0.0)|Other:(,3.0.0]</d:Dependencies>
    </m:properties></content></entry></feed>`;
  const result = parseGalleryFeed(xml);
  assert.equal(result.entries.length, 1);
  assert.equal(result.entries[0].title, 'Example & Tools');
  assert.equal(result.entries[0].isAbsoluteLatest, true);
  assert.equal(result.nextLink, '/api/v2/Packages?$skip=1&$top=1');
  assert.deepEqual(result.entries[0].dependencies, [
    { name: 'Core', versionRange: '[1.0.0,2.0.0)' },
    { name: 'Other', versionRange: '(,3.0.0]' },
  ]);
});

test('dependency parser preserves NuGet range delimiters and removes duplicate declarations', () => {
  assert.deepEqual(parseGalleryDependencies('Core:[1.0,2.0)|Core:[1.0,2.0]'), [
    { name: 'Core', versionRange: '[1.0,2.0)' },
    { name: 'Core', versionRange: '[1.0,2.0]' },
  ]);
});

test('NuGet ranges support exact, open, bounded, and union ranges', () => {
  assert.equal(versionMatchesRange('1.5.0', '[1.0.0,2.0.0)'), true);
  assert.equal(versionMatchesRange('2.0.0', '[1.0.0,2.0.0)'), false);
  assert.equal(versionMatchesRange('1.0.0', '(,1.0.0)'), false);
  assert.equal(versionMatchesRange('2.0.0', '(,3.0.0]'), true);
  assert.equal(versionMatchesRange('1.0.0', '[1.0.0]'), true);
  assert.equal(versionMatchesRange('2.5.0', '[1.0.0,2.0.0)|[2.5.0,3.0.0)'), true);
  assert.equal(versionMatchesRange('2.1.0', 'not-a-range'), null);
  assert.equal(parseNugetRange('[1.0.0,)')[0].max, null);
});

test('version comparison handles prereleases and OSV introduced zero ranges', () => {
  assert.ok(compareVersions('1.0.0', '1.0.0-rc.1') > 0);
  assert.equal(isVersionAffected('1.5.0', {
    affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }],
  }), true);
  assert.equal(isVersionAffected('2.0.0', {
    affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }],
  }), false);
});
