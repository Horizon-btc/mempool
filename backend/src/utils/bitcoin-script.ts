const opcodes = {
  OP_FALSE: 0,
  OP_0: 0,
  OP_PUSHDATA1: 76,
  OP_PUSHDATA2: 77,
  OP_PUSHDATA4: 78,
  OP_1NEGATE: 79,
  OP_PUSHNUM_NEG1: 79,
  OP_RESERVED: 80,
  OP_TRUE: 81,
  OP_1: 81,
  OP_2: 82,
  OP_3: 83,
  OP_4: 84,
  OP_5: 85,
  OP_6: 86,
  OP_7: 87,
  OP_8: 88,
  OP_9: 89,
  OP_10: 90,
  OP_11: 91,
  OP_12: 92,
  OP_13: 93,
  OP_14: 94,
  OP_15: 95,
  OP_16: 96,
  OP_PUSHNUM_1: 81,
  OP_PUSHNUM_2: 82,
  OP_PUSHNUM_3: 83,
  OP_PUSHNUM_4: 84,
  OP_PUSHNUM_5: 85,
  OP_PUSHNUM_6: 86,
  OP_PUSHNUM_7: 87,
  OP_PUSHNUM_8: 88,
  OP_PUSHNUM_9: 89,
  OP_PUSHNUM_10: 90,
  OP_PUSHNUM_11: 91,
  OP_PUSHNUM_12: 92,
  OP_PUSHNUM_13: 93,
  OP_PUSHNUM_14: 94,
  OP_PUSHNUM_15: 95,
  OP_PUSHNUM_16: 96,
  OP_NOP: 97,
  OP_VER: 98,
  OP_IF: 99,
  OP_NOTIF: 100,
  OP_VERIF: 101,
  OP_VERNOTIF: 102,
  OP_ELSE: 103,
  OP_ENDIF: 104,
  OP_VERIFY: 105,
  OP_RETURN: 106,
  OP_TOALTSTACK: 107,
  OP_FROMALTSTACK: 108,
  OP_2DROP: 109,
  OP_2DUP: 110,
  OP_3DUP: 111,
  OP_2OVER: 112,
  OP_2ROT: 113,
  OP_2SWAP: 114,
  OP_IFDUP: 115,
  OP_DEPTH: 116,
  OP_DROP: 117,
  OP_DUP: 118,
  OP_NIP: 119,
  OP_OVER: 120,
  OP_PICK: 121,
  OP_ROLL: 122,
  OP_ROT: 123,
  OP_SWAP: 124,
  OP_TUCK: 125,
  OP_CAT: 126,
  OP_SUBSTR: 127,
  OP_LEFT: 128,
  OP_RIGHT: 129,
  OP_SIZE: 130,
  OP_INVERT: 131,
  OP_AND: 132,
  OP_OR: 133,
  OP_XOR: 134,
  OP_EQUAL: 135,
  OP_EQUALVERIFY: 136,
  OP_RESERVED1: 137,
  OP_RESERVED2: 138,
  OP_1ADD: 139,
  OP_1SUB: 140,
  OP_2MUL: 141,
  OP_2DIV: 142,
  OP_NEGATE: 143,
  OP_ABS: 144,
  OP_NOT: 145,
  OP_0NOTEQUAL: 146,
  OP_ADD: 147,
  OP_SUB: 148,
  OP_MUL: 149,
  OP_DIV: 150,
  OP_MOD: 151,
  OP_LSHIFT: 152,
  OP_RSHIFT: 153,
  OP_BOOLAND: 154,
  OP_BOOLOR: 155,
  OP_NUMEQUAL: 156,
  OP_NUMEQUALVERIFY: 157,
  OP_NUMNOTEQUAL: 158,
  OP_LESSTHAN: 159,
  OP_GREATERTHAN: 160,
  OP_LESSTHANOREQUAL: 161,
  OP_GREATERTHANOREQUAL: 162,
  OP_MIN: 163,
  OP_MAX: 164,
  OP_WITHIN: 165,
  OP_RIPEMD160: 166,
  OP_SHA1: 167,
  OP_SHA256: 168,
  OP_HASH160: 169,
  OP_HASH256: 170,
  OP_CODESEPARATOR: 171,
  OP_CHECKSIG: 172,
  OP_CHECKSIGVERIFY: 173,
  OP_CHECKMULTISIG: 174,
  OP_CHECKMULTISIGVERIFY: 175,
  OP_NOP1: 176,
  OP_NOP2: 177,
  OP_CHECKLOCKTIMEVERIFY: 177,
  OP_CLTV: 177,
  OP_NOP3: 178,
  OP_CHECKSEQUENCEVERIFY: 178,
  OP_CSV: 178,
  OP_NOP4: 179,
  OP_NOP5: 180,
  OP_NOP6: 181,
  OP_NOP7: 182,
  OP_NOP8: 183,
  OP_NOP9: 184,
  OP_NOP10: 185,
  OP_CHECKSIGADD: 186,
  OP_PUBKEYHASH: 253,
  OP_PUBKEY: 254,
  OP_INVALIDOPCODE: 255,
};
// add unused opcodes
for (let i = 187; i <= 255; i++) {
  opcodes[`OP_RETURN_${i}`] = i;
}

export { opcodes };

/** extracts m and n from a multisig script (asm), returns nothing if it is not a multisig script */
export function parseMultisigScript(script: string): void | { m: number, n: number } {
  if (!script?.length) {
    return;
  }
  const ops = script.split(' ');
  if (ops.length < 3 || ops.pop() !== 'OP_CHECKMULTISIG') {
    return;
  }
  const opN = ops.pop();
  if (!opN) {
    return;
  }
  if (opN !== 'OP_0' && !opN.startsWith('OP_PUSHNUM_')) {
    return;
  }
  const n = parseInt(opN.match(/[0-9]+/)?.[0] || '', 10);
  if (ops.length < n * 2 + 1) {
    return;
  }
  // pop n public keys
  for (let i = 0; i < n; i++) {
    if (!/^0((2|3)\w{64}|4\w{128})$/.test(ops.pop() || '')) {
      return;
    }
    if (!/^OP_PUSHBYTES_(33|65)$/.test(ops.pop() || '')) {
      return;
    }
  }
  const opM = ops.pop();
  if (!opM) {
    return;
  }
  if (opM !== 'OP_0' && !opM.startsWith('OP_PUSHNUM_')) {
    return;
  }
  const m = parseInt(opM.match(/[0-9]+/)?.[0] || '', 10);

  if (ops.length) {
    return;
  }

  return { m, n };
}

export function getVarIntLength(n: number): number {
  if (n < 0xfd) {
    return 1;
  } else if (n <= 0xffff) {
    return 3;
  } else if (n <= 0xffffffff) {
    return 5;
  } else {
    return 9;
  }
}

// unproven pubkeys a script may carry before the rest count as data (Bitcoin Knots policy)
const MAX_UNPROVEN_PUBKEYS = 10;
const MAX_PUBKEYS_PER_MULTISIG = 20;
const COMPRESSED_PUBKEY_SIZE = 33;

/**
 * Bytes a script (hex) carries in pubkeys that no signature can prove, ported from Bitcoin Knots.
 *
 * A key in an m-of-n that nothing signs for authorizes nothing, so what it holds is payload rather
 * than a spending condition. That is how BPUB publishes files, as 1-of-15 multisig witness scripts
 * of ground secp256k1 points. Ordinary multisig carries a couple of such keys, hence the tolerance.
 *
 * @param stack the items that carry the spend's signatures, with the script last: the witness,
 *              or the scriptSig pushes of a P2SH spend
 */
export function unprovenPubkeyBytes(script: string, stack?: string[]): number {
  // a script needs more than MAX_UNPROVEN_PUBKEYS pubkey pushes before anything counts
  if (!script || script.length < (MAX_UNPROVEN_PUBKEYS + 1) * (COMPRESSED_PUBKEY_SIZE + 1) * 2) {
    return 0;
  }
  const size = script.length / 2;
  const byteAt = (i: number): number => parseInt(script.slice(i * 2, i * 2 + 2), 16);

  let pubkeys = 0;
  let provable = 0;
  // the current run of adjacent pubkey pushes and the count that opened it, since only
  // a well-formed <m> <pubkey>*n <n> OP_CHECKMULTISIG credits m
  let runKeys = 0;
  let runOpenedBy = -1;
  // well-formed <m> <pubkey>*n <n> that end a branch, credited when OP_CHECKMULTISIG follows the
  // conditional (unlike Knots, which charges federation scripts whose branches share one
  // OP_CHECKMULTISIG, such as Liquid's former peg-out script)
  let branchCredit = 0;
  // keys in the current push run, which are dropped data rather than pubkeys if a drop balances it
  let pushRunKeys = 0;
  let insideNoop = 0;
  let lastOpcode = opcodes.OP_INVALIDOPCODE;
  let lastCount = -1;
  let lastIsPush = false;

  for (let pc = 0; pc < size;) {
    const opcode = byteAt(pc++);
    let pushSize = 0;
    // the m or n of an m-of-n, which above 16 is a minimal one byte push rather than an OP_N
    let count = -1;
    if (opcode <= opcodes.OP_PUSHDATA4) {
      if (opcode < opcodes.OP_PUSHDATA1) {
        pushSize = opcode;
      } else {
        const width = opcode === opcodes.OP_PUSHDATA1 ? 1 : (opcode === opcodes.OP_PUSHDATA2 ? 2 : 4);
        if (pc + width > size) {
          return 0;
        }
        for (let i = width - 1; i >= 0; i--) {
          pushSize = pushSize * 256 + byteAt(pc + i);
        }
        pc += width;
      }
      if (pc + pushSize > size) {
        // unparsable scripts are all data anyway
        return 0;
      }
      if (opcode === 1 && byteAt(pc) > 16 && byteAt(pc) <= MAX_PUBKEYS_PER_MULTISIG) {
        count = byteAt(pc);
      }
      pc += pushSize;
    } else if (opcode >= opcodes.OP_1 && opcode <= opcodes.OP_16) {
      count = opcode - opcodes.OP_1 + 1;
    }

    if (insideNoop) {
      // OP_FALSE OP_IF envelopes are inscriptions, not pubkeys
      if (opcode === opcodes.OP_IF || opcode === opcodes.OP_NOTIF) {
        insideNoop++;
      } else if (opcode === opcodes.OP_ENDIF) {
        insideNoop--;
      }
    } else if (opcode === opcodes.OP_IF && lastOpcode === opcodes.OP_FALSE) {
      insideNoop = 1;
    } else if (opcode <= opcodes.OP_PUSHDATA4 && (pushSize === COMPRESSED_PUBKEY_SIZE || pushSize === 65)) {
      if (!runKeys) {
        runOpenedBy = lastCount;
      }
      runKeys++;
      pushRunKeys++;
      pubkeys++;
    } else if ((opcode === opcodes.OP_DROP || opcode === opcodes.OP_2DROP) && lastIsPush) {
      pubkeys -= pushRunKeys;
      runKeys = 0;
    } else if (opcode === opcodes.OP_CHECKSIG || opcode === opcodes.OP_CHECKSIGVERIFY) {
      provable++;
      runKeys = 0;
    } else if (opcode === opcodes.OP_CHECKMULTISIG || opcode === opcodes.OP_CHECKMULTISIGVERIFY) {
      // padding or reordering the keys forfeits the credit
      if (runOpenedBy > 0 && lastCount > 0 && lastCount === runKeys) {
        provable += runOpenedBy;
      } else if (lastOpcode === opcodes.OP_ENDIF) {
        provable += branchCredit;
      }
      branchCredit = 0;
      runKeys = 0;
    } else if ((opcode === opcodes.OP_ELSE || opcode === opcodes.OP_ENDIF) && runOpenedBy > 0 && lastCount > 0 && lastCount === runKeys) {
      branchCredit += runOpenedBy;
      runKeys = 0;
    } else if (count < 0) {
      // a key count sits on both ends of a multisig, so only other opcodes break the run
      runKeys = 0;
    }

    const isPush = opcode <= opcodes.OP_16 && opcode !== opcodes.OP_RESERVED;
    if (!isPush) {
      pushRunKeys = 0;
    }
    lastOpcode = opcode;
    lastCount = count;
    lastIsPush = isPush;
  }

  // a script can name more signatures than the spender supplies, including in branches that never
  // run, so count the signature-shaped items of the spend (DER plus sighash byte, or BIP340)
  if (stack?.length) {
    const signatures = stack.slice(0, -1).filter(item => item.length >= 128 && item.length <= 146).length;
    provable = Math.min(provable, signatures);
  }

  // an uncompressed key carries no more payload than a compressed one, since only x is free
  return Math.max(0, pubkeys - provable - MAX_UNPROVEN_PUBKEYS) * COMPRESSED_PUBKEY_SIZE;
}

/**
 * DATUM pools, by slug, that mark the templates they build themselves with a private tag: their
 * own tag repeated where a DATUM coinbase carries the miner's. For these pools that tag is the
 * only sign of a pool-built block, so every other coinbase came through a DATUM gateway, even
 * one whose miner left their own tag empty.
 */
const PRIVATE_TAG_POOLS = ['convoy'];

export function tagsPrivateTemplates(poolSlug: string | undefined): boolean {
  return !!poolSlug && PRIVATE_TAG_POOLS.includes(poolSlug);
}

/** Extracts miner names from a DATUM coinbase transaction, or null when the pool's private tag says it built the template itself */
export function parseDATUMTemplateCreator(coinbaseRaw: string, poolSlug?: string): string[] | null {
  const bytes: number[] = [];
  for (let c = 0; c < coinbaseRaw.length; c += 2) {
      bytes.push(parseInt(coinbaseRaw.slice(c, c + 2), 16));
  }

  // Skip block height
  let tagLengthByte = 1 + bytes[0];

  let tagsLength = bytes[tagLengthByte];
  if (tagsLength == 0x4c) {
    tagLengthByte += 1;
    tagsLength = bytes[tagLengthByte];
  }

  const tagStart = tagLengthByte + 1;
  const tags = bytes.slice(tagStart, tagStart + tagsLength);
  let tagString = String.fromCharCode(...tags);
  tagString = tagString.replace('\x00', '');

  const minerNames = tagString.split('\x0f').map((name) => name.replace(/[^a-zA-Z0-9 ]/g, ''));

  if (tagsPrivateTemplates(poolSlug) && minerNames.length > 1) {
    const poolTag = minerNames[0].trim();
    if (poolTag.length && minerNames[1].trim() === poolTag) {
      return null;
    }
  }

  return minerNames;
}

/** Extracts miner names from a DMND coinbase transaction */
export function parseDMNDTemplateCreator(coinbaseRaw: string): string[] {
  try {
    if (!coinbaseRaw || coinbaseRaw.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(coinbaseRaw)) {
      return [];
    }

    const bytes = Buffer.from(coinbaseRaw, 'hex');
    const blockHeightLength = bytes[0];
    const tagDelimiterIndex = 1 + blockHeightLength;
    if (bytes.length <= tagDelimiterIndex || bytes[tagDelimiterIndex] !== 0x00) {
      return [];
    }

    const tagStart = tagDelimiterIndex + 1;
    const tagEnd = bytes.indexOf(0x00, tagStart);
    const tags = bytes.subarray(tagStart, tagEnd === -1 ? undefined : tagEnd);
    return tags.toString('utf8').split('/').slice(1, -1);
  } catch {
    return [];
  }
}
