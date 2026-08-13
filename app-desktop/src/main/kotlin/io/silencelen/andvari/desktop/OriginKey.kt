package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.OriginCanon

/**
 * (origin, userId) namespacing key — design 2026-07-15-multi-tenant-endpoints §4.2 (B2-3/B2-7).
 *
 *     originKey = hex(sha256(canonical origin)).take(16)
 *     canonical = lowercase `scheme://host[:non-default port]`
 *
 * The byte-parity contract with android and the extension used to be a COMMENT in this file
 * ("BYTE-PARITY CONTRACT (binding)") over ~100 lines hand-copied between the two Kotlin apps,
 * guarded only by the same literals written out in two separate test modules — and the copies
 * had already drifted in shape. It is now a compile-time fact: the rules, the vectors and their
 * rationale live once in core's [OriginCanon] (`core/src/jvmShared`, compiled into both apps),
 * and these are this module's local names for them. Read the rules there; change them there.
 */
internal fun originKey(baseUrl: String): String = OriginCanon.originKey(baseUrl)

/**
 * A path-safe rendering of a SERVER-SUPPLIED identifier for use as a path segment or filename
 * fragment. Under the endpoint-agnostic model the server is untrusted, and `userId` is
 * server-minted: a hostile server that names a user `../<victim>` must not alias its namespace
 * into another origin's (§4.1 rule 2 holds against hostile INPUTS, not just hostile timing).
 */
internal fun pathSafe(raw: String): String = OriginCanon.pathSafe(raw)

/** The pinned canonical origin form (see [OriginCanon]). Exposed for tests. */
internal fun canonicalOrigin(url: String): String = OriginCanon.canonicalOrigin(url)

/**
 * Strict validation + canonicalization of a USER-TYPED server address for the manual switch
 * (design §4.4). A userinfo/path-bearing input is a bearer-credential PHISHING vector —
 * `https://real.host@evil.example` lets the Trust Gate show a reassuring host while the HTTP
 * stack actually dials `evil.example`, and a manual switch commits immediately, so a subsequent
 * sign-in hands the attacker an offline-crackable authKey of the real master password (the B2-6
 * threat). Null = refuse.
 */
internal fun canonicalServerOrigin(input: String): String? = OriginCanon.canonicalServerOrigin(input)
