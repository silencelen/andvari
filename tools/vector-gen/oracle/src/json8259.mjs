// A JSON reader that accepts exactly RFC 8259 and nothing more, written by hand so that no
// library's leniency decides a verdict (design §2.4, the host JSON row).
//
// It refuses: a bare token, NaN, Infinity, a trailing comma, anything but white space after the
// value, a key that appears twice in the TOP-LEVEL object (compared after unescaping), and more than
// `maxDepth` containers open at once (the outermost one counts).

const WS = new Set([' ', '\t', '\n', '\r']);

class Refused extends Error {}

/**
 * The most containers (`{` or `[`) open at once in `text`, counted on the characters in one pass
 * with no recursion and no stack: a bracket inside a string does not count, and a backslash inside a
 * string takes the next character with it. For text that is RFC 8259 JSON this is its nesting depth.
 * For any other text the number means nothing, and it need not: such text is refused whatever its
 * depth. This is how the 32-container limit is decided "on the bytes" (design §2.4, the host JSON
 * row), before any parser sees the text: an offer of a thousand open brackets costs one loop.
 */
export function maxOpenContainers(text) {
  let open = 0;
  let most = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === '\\') i++;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === '{' || c === '[') {
      open++;
      if (open > most) most = open;
    } else if (c === '}' || c === ']') open--;
  }
  return most;
}

export function parseStrictJson(text, { maxDepth = 32 } = {}) {
  let pos = 0;
  let depth = 0;
  const fail = () => {
    throw new Refused();
  };
  const ws = () => {
    while (pos < text.length && WS.has(text[pos])) pos++;
  };
  const string = () => {
    if (text[pos] !== '"') fail();
    pos++;
    let out = '';
    for (;;) {
      if (pos >= text.length) fail();
      const c = text[pos++];
      if (c === '"') return out;
      if (c.charCodeAt(0) < 0x20) fail();
      if (c !== '\\') {
        out += c;
        continue;
      }
      const e = text[pos++];
      const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
      if (Object.hasOwn(simple, e)) out += simple[e];
      else if (e === 'u') {
        const h = text.slice(pos, pos + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(h)) fail();
        out += String.fromCharCode(parseInt(h, 16));
        pos += 4;
      } else fail();
    }
  };
  const number = () => {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(pos));
    if (!m) fail();
    pos += m[0].length;
    return Number(m[0]);
  };
  const open = () => {
    depth++;
    if (depth > maxDepth) fail();
  };
  const value = (top) => {
    ws();
    const c = text[pos];
    if (c === '{') {
      open();
      pos++;
      const obj = {};
      const seen = new Set();
      ws();
      if (text[pos] === '}') {
        pos++;
        depth--;
        return obj;
      }
      for (;;) {
        ws();
        const key = string();
        if (top && seen.has(key)) fail(); // a key twice at the top level, whichever value comes last
        seen.add(key);
        ws();
        if (text[pos] !== ':') fail();
        pos++;
        obj[key] = value(false);
        ws();
        if (text[pos] === ',') {
          pos++;
          continue;
        }
        if (text[pos] === '}') {
          pos++;
          depth--;
          return obj;
        }
        fail();
      }
    }
    if (c === '[') {
      open();
      pos++;
      const arr = [];
      ws();
      if (text[pos] === ']') {
        pos++;
        depth--;
        return arr;
      }
      for (;;) {
        arr.push(value(false));
        ws();
        if (text[pos] === ',') {
          pos++;
          continue;
        }
        if (text[pos] === ']') {
          pos++;
          depth--;
          return arr;
        }
        fail();
      }
    }
    if (c === '"') return string();
    if (text.startsWith('true', pos)) {
      pos += 4;
      return true;
    }
    if (text.startsWith('false', pos)) {
      pos += 5;
      return false;
    }
    if (text.startsWith('null', pos)) {
      pos += 4;
      return null;
    }
    if (c === '-' || (c >= '0' && c <= '9')) return number();
    return fail();
  };
  try {
    const v = value(true);
    ws();
    if (pos !== text.length) fail();
    return { ok: true, value: v };
  } catch (e) {
    if (e instanceof Refused) return { ok: false };
    throw e;
  }
}
