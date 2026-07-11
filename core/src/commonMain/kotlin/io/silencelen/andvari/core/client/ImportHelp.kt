package io.silencelen.andvari.core.client

/** The per-source "How do I export from…?" help table — the ONE surviving per-source
 *  surface of the universal importer (design 2026-07-11). Steps are best-effort export
 *  navigation docs (current as of 2026-07), NOT contracts — parsing never consults them;
 *  header detection is authoritative (CsvImport). Shared by Android + desktop; web keeps
 *  its own content-aligned twin (non-KMP). */
object ImportHelp {
    data class Source(val label: String, val steps: List<String>, val note: String? = null)

    val SOURCES: List<Source> = listOf(
        Source(
            label = "Chrome",
            steps = listOf(
                "Open chrome://password-manager/settings (Menu ⋮ → Passwords and autofill → Google Password Manager → Settings).",
                "Under “Export passwords”, choose Download file.",
                "Confirm with your device sign-in and save the CSV.",
            ),
        ),
        Source(
            label = "Edge",
            steps = listOf(
                "Open edge://wallet/passwords.",
                "Click ⋯ (More options) → Export passwords.",
                "Confirm with your device sign-in and save the CSV.",
            ),
        ),
        Source(
            label = "Brave",
            steps = listOf(
                "Open brave://password-manager/settings.",
                "Under “Export passwords”, choose Download file.",
                "Confirm with your device sign-in and save the CSV.",
            ),
        ),
        Source(
            label = "Opera",
            steps = listOf(
                "Open opera://settings/passwords.",
                "Next to “Saved Passwords”, click ⋮ → Export passwords.",
                "Confirm with your device sign-in and save the CSV.",
            ),
        ),
        Source(
            label = "Firefox",
            steps = listOf(
                "Open about:logins (Menu ☰ → Passwords).",
                "Click ⋯ (top right) → Export passwords…",
                "Confirm with your device sign-in and save the CSV.",
            ),
        ),
        Source(
            label = "Bitwarden",
            steps = listOf(
                "In the Bitwarden web vault or desktop app: Tools → Export vault.",
                "File format: .csv (not .json).",
                "Confirm with your master password and save the file.",
            ),
        ),
        Source(
            label = "1Password",
            steps = listOf(
                "In the 1Password desktop app (version 8 or newer): File → Export → your account.",
                "Choose the CSV format, confirm with your account password, and save the file.",
            ),
            note = "1Password 7 and older export a different CSV shape — update to 1Password 8 or newer, or route through Bitwarden/another CSV export as an intermediate.",
        ),
        Source(
            label = "LastPass",
            steps = listOf(
                "Sign in to your vault at lastpass.com.",
                "Open Advanced Options in the left menu → Export.",
                "Confirm with your master password — LastPass downloads a lastpass_export.csv file.",
            ),
            note = "Use that downloaded file directly. Don’t copy CSV text out of a browser tab into a file — that route mangles characters like “&”.",
        ),
    )
}
