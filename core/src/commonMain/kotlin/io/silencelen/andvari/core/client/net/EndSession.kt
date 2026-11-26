package io.silencelen.andvari.core.client.net

import io.silencelen.andvari.core.model.wire.RefreshRequest
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/**
 * `POST /api/v1/auth/end-session {refreshToken}` (spec 03 §2, index row 93): ends exactly the ONE session that issued
 * [refreshToken], and the access token issued with it; sibling sessions, the device row and the account's other devices
 * are untouched. A token its own refresh has already consumed reads as reuse at the server and ends every session of
 * that device row, so a caller awaits any refresh in flight and sends the NEWEST refresh token.
 *
 * For a lock that drops its token pair (a browser tab without the offline copy). A lock that keeps its pair to unlock
 * from it, and "Sign out" (the logout, row 12), do not use it.
 *
 * **Best effort, and it answers nothing.** The server answers `200 ok` whatever the token, so there is nothing to tell
 * the caller: no answer, a refusal and a success all return normally, and nothing of the request is retried. It goes
 * through the client's origin guard like any request that carries a credential (the refresh token is one): to an origin
 * whose pin is not in force nothing is sent. A token that is empty or longer than 4096 characters is not sent. It sends
 * no bearer.
 *
 * **It never throws to a caller that is locking.** Every failure of the call is swallowed here (that is its contract,
 * not a lost failure: the caller has dropped the pair whatever happens). Only the caller's OWN cancellation propagates,
 * as from any suspending call; a lock that must send it runs it in a non-cancellable context.
 */
suspend fun WireClient.endSession(refreshToken: String) {
    if (refreshToken.isEmpty() || refreshToken.length > MAX_REFRESH_TOKEN_CHARS) return
    try {
        val body = WireJson.json.encodeToString(RefreshRequest.serializer(), RefreshRequest(refreshToken))
        call(WireRoute.END_SESSION, bodyJson = body, authenticated = false, decode = { })
    } catch (e: CancellationException) {
        currentCoroutineContext().ensureActive()
    } catch (_: Throwable) {
        // Best effort: see the contract above.
    }
}

private const val MAX_REFRESH_TOKEN_CHARS = 4096
