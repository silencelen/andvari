Backups written by the 0.30.0 code, kept so that a later restore is tested on a file an old app really wrote.

backup-0.30.0-web.andvari
  Made at the commit that the tag v0.30.0 names, by the web app's own buildBackup (web/src/export/export.ts), with fixed content:
  a personal vault with a login, a note and a card; a shared vault "Family" (role owner) and a shared vault "Work"
  (role writer) with two items each; two attached files in the file (statement.pdf, 70,000 bytes, more than one
  64 KiB chunk of a sealed section; codes.txt, 36 bytes); one name in each list of what the file could not hold
  (one undecryptable item, tax-archive.zip over the cap, scan.pdf not fetched); exported at 1763000000000 from
  https://vault.example.org; file id f0f0f0f0-f0f0-4f0f-8f0f-f0f0f0f0f0f2; passphrase "old backup pass phrase 0.30";
  Argon2id at 2 passes and 64 MiB.
  SHA-256 e7637f3dafeb680f90a42748d1bf2079e30a18cfc6dda50f23428bf5369c1d99
