import { inflateRawSync } from 'node:zlib';

export const ARCHIVE_LIMITS = Object.freeze({
  compressedBytes: 100 * 1024 * 1024,
  entryCount: 5000,
  entryBytes: 35 * 1024 * 1024,
  totalBytes: 150 * 1024 * 1024,
  compressionRatio: 500,
});

const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = (c & 1) ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC_TABLE[n] = c >>> 0;
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function findEndRecord(buffer) {
  const minimum = Math.max(0, buffer.length - 65_557);
  for (let offset = buffer.length - 22; offset >= minimum; offset--) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  throw new Error('ZIP end-of-central-directory record was not found.');
}

function normalizeArchivePath(name) {
  return name.replaceAll(String.fromCharCode(92), '/').normalize('NFC');
}

function safeArchivePath(name) {
  const normalized = normalizeArchivePath(name);
  return !normalized.startsWith('/')
    && !/^[a-z]:/i.test(normalized)
    && !normalized.split('/').includes('..')
    && !normalized.includes(String.fromCharCode(0));
}

function isScript(name) {
  return /\.(?:ps1|psm1|psd1|ps1xml|pssc)$/i.test(name);
}

function isBinary(name) {
  return /\.(?:dll|exe|msi|com|sys|bin|scr|so|dylib)$/i.test(name);
}

function decodeText(buffer) {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString('utf16le');
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const swapped = Buffer.from(buffer.subarray(2));
    for (let i = 0; i + 1 < swapped.length; i += 2) [swapped[i], swapped[i + 1]] = [swapped[i + 1], swapped[i]];
    return swapped.toString('utf16le');
  }
  if (buffer.length >= 3 && buffer.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) return buffer.subarray(3).toString('utf8');
  return buffer.toString('utf8');
}

function readUtf8Name(buffer, start, length, utf8) {
  return buffer.subarray(start, start + length).toString(utf8 ? 'utf8' : 'latin1');
}

export function inspectNupkg(buffer, limits = ARCHIVE_LIMITS) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 22) throw new Error('Package archive is too small to be a ZIP file.');
  if (buffer.length > limits.compressedBytes) {
    throw new Error('Package archive exceeds the configured ' + Math.ceil(limits.compressedBytes / (1024 * 1024)) + ' MiB compressed-size limit.');
  }
  const end = findEndRecord(buffer);
  const diskNumber = buffer.readUInt16LE(end + 4);
  const centralDisk = buffer.readUInt16LE(end + 6);
  const diskEntries = buffer.readUInt16LE(end + 8);
  const entryCount = buffer.readUInt16LE(end + 10);
  const centralSize = buffer.readUInt32LE(end + 12);
  const centralOffset = buffer.readUInt32LE(end + 16);
  const commentLength = buffer.readUInt16LE(end + 20);
  if (diskNumber !== 0 || centralDisk !== 0 || diskEntries !== entryCount) throw new Error('Multi-volume ZIP archives are not supported.');
  if (entryCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) throw new Error('ZIP64 archives are not supported within the configured package limits.');
  if (end + 22 + commentLength > buffer.length || centralOffset + centralSize > end) throw new Error('ZIP central directory is outside the archive bounds.');
  if (entryCount > limits.entryCount) {
    throw new Error('Package archive contains more than ' + limits.entryCount.toLocaleString('en-US') + ' entries.');
  }

  const result = { files: [], binaries: [], inventory: [], warnings: [], complete: true, entryCount };
  let totalUncompressed = 0;
  let offset = centralOffset;
  const names = new Set();

  for (let index = 0; index < entryCount; index++) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== 0x02014b50) throw new Error('Malformed ZIP central directory entry.');
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const crc = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const entryCommentLength = buffer.readUInt16LE(offset + 32);
    const diskStart = buffer.readUInt16LE(offset + 34);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const nameStart = offset + 46;
    const endEntry = nameStart + fileNameLength + extraLength + entryCommentLength;
    if (endEntry > buffer.length) throw new Error('ZIP central directory entry exceeds the archive bounds.');
    if (diskStart !== 0 || compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
      result.complete = false;
      result.warnings.push('Unsupported ZIP64 or multi-volume entry.');
      offset = endEntry;
      continue;
    }

    const name = readUtf8Name(buffer, nameStart, fileNameLength, Boolean(flags & 0x0800));
    const normalized = normalizeArchivePath(name).replace(/^\.\//, '');
    const directory = normalized.endsWith('/');
    const validPath = safeArchivePath(normalized);
    const duplicate = names.has(normalized);
    if (!validPath) {
      result.complete = false;
      result.warnings.push('Unsafe archive entry path was ignored.');
    }
    if (duplicate) {
      result.complete = false;
      result.warnings.push('Duplicate archive entry path was ignored.');
    }
    names.add(normalized);
    totalUncompressed += uncompressedSize;
    if (totalUncompressed > limits.totalBytes) {
      result.complete = false;
      result.warnings.push('Expanded package size exceeds the configured ' + Math.ceil(limits.totalBytes / (1024 * 1024)) + ' MiB limit.');
      break;
    }
    const extension = normalized.split('.').at(-1)?.toLocaleLowerCase('en-US') || '';
    if (!directory && validPath && !duplicate) {
      result.inventory.push({ path: normalized, size: uncompressedSize, crc32: crc.toString(16).padStart(8, '0'), extension });
    }

    const isNuspec = normalized.toLocaleLowerCase('en-US').endsWith('.nuspec');
    const binary = !directory && validPath && !duplicate && isBinary(normalized);
    const eligible = !directory && validPath && !duplicate && (isScript(normalized) || isNuspec || binary);
    if (eligible) {
      if (uncompressedSize > limits.entryBytes) {
        result.complete = false;
        result.warnings.push('A package file exceeds the ' + Math.ceil(limits.entryBytes / (1024 * 1024)) + ' MiB per-file analysis limit.');
        offset = endEntry;
        continue;
      }
      if ((flags & 1) !== 0) {
        result.complete = false;
        result.warnings.push('Encrypted package content cannot be inspected.');
        offset = endEntry;
        continue;
      }
      if (method !== 0 && method !== 8) {
        result.complete = false;
        result.warnings.push('Unsupported ZIP compression method.');
        offset = endEntry;
        continue;
      }
      if (uncompressedSize > 1024 * 1024 && (compressedSize === 0 || uncompressedSize / compressedSize > limits.compressionRatio)) {
        result.complete = false;
        result.warnings.push('A package file exceeds the configured ' + limits.compressionRatio + ':1 compression ratio limit.');
        offset = endEntry;
        continue;
      }
      if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== 0x04034b50) throw new Error('Malformed ZIP local file header.');
      const localNameLength = buffer.readUInt16LE(localOffset + 26);
      const localExtraLength = buffer.readUInt16LE(localOffset + 28);
      const dataStart = localOffset + 30 + localNameLength + localExtraLength;
      const dataEnd = dataStart + compressedSize;
      if (dataStart > buffer.length || dataEnd > buffer.length) throw new Error('ZIP file data is outside the archive bounds.');
      const compressed = buffer.subarray(dataStart, dataEnd);
      let body;
      try {
        body = method === 0
          ? Buffer.from(compressed)
          : inflateRawSync(compressed, { maxOutputLength: Math.min(limits.totalBytes, limits.entryBytes) + 1 });
      } catch {
        result.complete = false;
        result.warnings.push('A package file could not be safely decompressed.');
        offset = endEntry;
        continue;
      }
      if (body.length !== uncompressedSize || crc32(body) !== crc) {
        result.complete = false;
        result.warnings.push('A package file failed its ZIP size or checksum validation.');
        offset = endEntry;
        continue;
      }
      if (binary) {
        result.binaries.push({ path: normalized, size: uncompressedSize, content: body });
      } else {
        result.files.push({
          path: normalized,
          size: uncompressedSize,
          kind: isNuspec ? 'nuspec' : 'script',
          text: decodeText(body),
        });
      }
    }
    offset = endEntry;
  }
  if (offset > centralOffset + centralSize) throw new Error('ZIP central directory entry count or size is inconsistent.');
  return result;
}
