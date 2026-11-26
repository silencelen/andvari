-- The baseline 'onboarding-trust-1' exactly as the server created it before decoy requests (15 November 2026)
-- (Db.SCHEMA in server/src/main/kotlin/io/silencelen/andvari/server/Db.kt as it stood then).
-- Frozen: never edit this file to follow a change of the baseline. A database made from it must still start
-- and then match the baseline (BaselineCatchUpTest), or carry a marker this build refuses.
-- Since this file: the change of 15 November 2026 let recovery_requests.userId be NULL (a decoy request), and that of 16 November 2026 added
-- recovery_requests.commitHash and recovery_requests.commitAttempts.
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE users(
     userId TEXT PRIMARY KEY,
     email TEXT UNIQUE NOT NULL,
     displayName TEXT NOT NULL,
     kdfSalt TEXT NOT NULL,
     kdfParams TEXT NOT NULL,
     verifier TEXT NOT NULL,
     wrappedUvk TEXT NOT NULL,
     identityPub TEXT NOT NULL,
     encryptedIdentitySeed TEXT NOT NULL,
     genesis TEXT NOT NULL,
     personalVaultId TEXT NOT NULL,
     role TEXT NOT NULL CHECK(role IN ('operator','member')),
     status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
     disabledAt INTEGER,
     recovery TEXT NOT NULL DEFAULT 'private' CHECK(recovery IN ('private','operator')),
     requireLink INTEGER NOT NULL DEFAULT 0,
     recoveryConfirmed INTEGER NOT NULL DEFAULT 0,
     quotaAccountBytes INTEGER,
     quotaItems INTEGER,
     quotaOwnedSharedVaults INTEGER,
     quotaOpenLinks INTEGER,
     ageConfirmed INTEGER NOT NULL DEFAULT 0,
     createdAt INTEGER NOT NULL,
     registeredVia TEXT NOT NULL CHECK(registeredVia IN ('ticket','link','enrol','setup')),
     totpSecret TEXT,
     totpPendingSecret TEXT,
     totpEnrolledAt INTEGER,
     totpLastStep INTEGER NOT NULL DEFAULT 0
   );
CREATE UNIQUE INDEX users_one_operator ON users(role) WHERE role='operator';
CREATE INDEX idx_users_registered ON users(createdAt, registeredVia);
CREATE TABLE devices(
     deviceId TEXT PRIMARY KEY,
     userId TEXT NOT NULL REFERENCES users(userId),
     platform TEXT NOT NULL,
     name TEXT NOT NULL,
     clientVersion TEXT,
     how TEXT NOT NULL CHECK(how IN ('registered','password','linked','recovered')),
     linkedFrom TEXT,
     deviceSecretHash TEXT,
     createdAt INTEGER NOT NULL,
     lastSeenAt INTEGER,
     revokedAt INTEGER,
     signedOutAt INTEGER
   );
CREATE INDEX idx_devices_user ON devices(userId);
CREATE TABLE sessions(
     sessionId TEXT PRIMARY KEY,
     deviceId TEXT NOT NULL REFERENCES devices(deviceId),
     userId TEXT NOT NULL REFERENCES users(userId),
     accessHash TEXT UNIQUE NOT NULL,
     accessExpiresAt INTEGER NOT NULL,
     refreshHash TEXT UNIQUE NOT NULL,
     refreshExpiresAt INTEGER NOT NULL,
     refreshConsumedAt INTEGER,
     clientPlatform TEXT NOT NULL,
     passwordAt INTEGER,
     createdAt INTEGER NOT NULL,
     revokedAt INTEGER
   );
CREATE INDEX idx_sessions_user ON sessions(userId);
CREATE INDEX idx_sessions_device ON sessions(deviceId);
CREATE TABLE member_recovery(
     userId TEXT PRIMARY KEY REFERENCES users(userId),
     recoveryWrappedUvk TEXT NOT NULL,
     recoveryVerifier TEXT NOT NULL,
     pieceId TEXT NOT NULL,
     setupDeviceId TEXT,
     updatedAt INTEGER NOT NULL
   );
CREATE TABLE escrow(
     userId TEXT PRIMARY KEY REFERENCES users(userId),
     sealed TEXT NOT NULL,
     fingerprint TEXT NOT NULL,
     updatedAt INTEGER NOT NULL
   );
CREATE TABLE account_state(
     userId TEXT PRIMARY KEY REFERENCES users(userId),
     sealedState TEXT NOT NULL,
     seq INTEGER NOT NULL,
     updatedAt INTEGER NOT NULL
   );
CREATE TABLE personal_wrap(
     userId TEXT PRIMARY KEY REFERENCES users(userId),
     vaultId TEXT NOT NULL,
     wrappedVk TEXT NOT NULL,
     updatedAt INTEGER NOT NULL
   );
CREATE TABLE usage_ledger(
     userId TEXT PRIMARY KEY REFERENCES users(userId),
     sealedUsage TEXT NOT NULL,
     updatedAt INTEGER NOT NULL
   );
CREATE TABLE retired_ids(idHash TEXT PRIMARY KEY);
CREATE TABLE vaults(
     vaultId TEXT PRIMARY KEY,
     type TEXT NOT NULL CHECK(type IN ('personal','shared')),
     rev INTEGER NOT NULL,
     metaBlob TEXT NOT NULL,
     createdAt INTEGER NOT NULL,
     logSeq INTEGER,
     logHash TEXT,
     logAt INTEGER,
     deletedAt INTEGER,
     purgeAt INTEGER,
     purgedAt INTEGER,
     deletedBy TEXT,
     deleteId TEXT,
     finalSeq INTEGER,
     finalHash TEXT,
     finalAt INTEGER,
     pendingOfferId TEXT,
     pendingOwnerId TEXT,
     pendingOfferExpiresAt INTEGER,
     logState TEXT
   );
CREATE INDEX idx_vaults_purge ON vaults(purgeAt) WHERE purgeAt IS NOT NULL;
CREATE TABLE vault_log(
     vaultId TEXT NOT NULL REFERENCES vaults(vaultId),
     seq INTEGER NOT NULL,
     hash TEXT NOT NULL,
     frame TEXT NOT NULL,
     actor TEXT NOT NULL,
     kind TEXT NOT NULL,
     at INTEGER NOT NULL,
     storedAt INTEGER NOT NULL,
     PRIMARY KEY(vaultId, seq)
   );
CREATE TABLE grants(
     vaultId TEXT NOT NULL REFERENCES vaults(vaultId),
     userId TEXT NOT NULL REFERENCES users(userId),
     role TEXT NOT NULL CHECK(role IN ('owner','writer','reader')),
     addedAt INTEGER NOT NULL,
     wrappedVk TEXT NOT NULL,
     signedGrant TEXT,
     rev INTEGER NOT NULL,
     revokedAt INTEGER,
     revokedReason TEXT CHECK(revokedReason IS NULL OR revokedReason IN ('member_remove','member_leave','vault_delete')),
     PRIMARY KEY(vaultId, userId)
   );
CREATE INDEX idx_grants_user ON grants(userId);
CREATE TABLE items(
     itemId TEXT PRIMARY KEY,
     vaultId TEXT NOT NULL REFERENCES vaults(vaultId),
     rev INTEGER NOT NULL,
     createdAt INTEGER NOT NULL,
     updatedAt INTEGER NOT NULL,
     deleted INTEGER NOT NULL DEFAULT 0,
     conflict INTEGER NOT NULL DEFAULT 0,
     formatVersion INTEGER NOT NULL,
     attachmentIds TEXT NOT NULL DEFAULT '[]',
     blob TEXT,
     blobSize INTEGER NOT NULL DEFAULT 0
   );
CREATE INDEX idx_items_vault_rev ON items(vaultId, rev);
CREATE INDEX idx_items_deleted_updated ON items(updatedAt) WHERE deleted=1;
CREATE TABLE item_versions(
     itemId TEXT NOT NULL,
     rev INTEGER NOT NULL,
     blob TEXT NOT NULL,
     formatVersion INTEGER NOT NULL,
     archivedAt INTEGER NOT NULL,
     PRIMARY KEY(itemId, rev)
   );
CREATE TABLE changes(
     rev INTEGER PRIMARY KEY AUTOINCREMENT,
     kind TEXT NOT NULL,
     entityId TEXT NOT NULL,
     vaultId TEXT,
     at INTEGER NOT NULL
   );
CREATE TABLE mutations(
     deviceId TEXT NOT NULL,
     mutationId TEXT NOT NULL,
     resultJson TEXT NOT NULL,
     createdAt INTEGER NOT NULL,
     userId TEXT,
     PRIMARY KEY(deviceId, mutationId)
   );
CREATE INDEX idx_mutations_user ON mutations(userId);
CREATE TABLE attachments(
     attachmentId TEXT PRIMARY KEY,
     itemId TEXT NOT NULL,
     vaultId TEXT NOT NULL,
     size INTEGER NOT NULL,
     sha256 TEXT NOT NULL,
     header TEXT NOT NULL,
     createdAt INTEGER NOT NULL
   );
CREATE INDEX idx_attachments_item ON attachments(itemId);
CREATE INDEX idx_attachments_vault ON attachments(vaultId);
CREATE TABLE connections(
     a TEXT NOT NULL,
     b TEXT NOT NULL,
     createdAt INTEGER NOT NULL,
     PRIMARY KEY(a, b),
     CHECK(a < b)
   );
CREATE INDEX idx_connections_b ON connections(b);
CREATE TABLE links(
     linkId TEXT PRIMARY KEY,
     kind TEXT NOT NULL CHECK(kind IN ('connect','register','enrol','setup')),
     creatorUserId TEXT,
     createdAt INTEGER NOT NULL,
     expiresAt INTEGER NOT NULL,
     offer TEXT NOT NULL,
     tokenHash TEXT,
     boundEmailHash TEXT,
     state TEXT NOT NULL CHECK(state IN ('open','answered','revoked','expired')),
     stateChangedAt INTEGER,
     answererUserId TEXT,
     answer TEXT,
     answeredAt INTEGER,
     deliveredAt INTEGER,
     reveal TEXT
   );
CREATE INDEX idx_links_creator ON links(creatorUserId);
CREATE TABLE device_links(
     linkId TEXT PRIMARY KEY,
     userId TEXT NOT NULL REFERENCES users(userId),
     deviceId TEXT NOT NULL,
     state TEXT NOT NULL CHECK(state IN ('open','claimed','revealed','approved')),
     expiresAt INTEGER NOT NULL,
     nPub TEXT,
     claimName TEXT,
     claimPlatform TEXT,
     commitN TEXT,
     claimMac TEXT,
     nonceE TEXT,
     nonceN TEXT,
     proofHash TEXT,
     outer TEXT,
     inner TEXT,
     approveMac TEXT,
     approvedBy TEXT,
     createdAt INTEGER NOT NULL,
     claimedAt INTEGER,
     revealedAt INTEGER,
     approvedAt INTEGER
   );
CREATE INDEX idx_device_links_user ON device_links(userId);
CREATE INDEX idx_device_links_device ON device_links(deviceId);
CREATE TABLE instance_setup(
     id INTEGER PRIMARY KEY CHECK(id=1),
     instanceId TEXT NOT NULL,
     name TEXT NOT NULL
   );
CREATE TABLE instance_cards(
     seq INTEGER PRIMARY KEY,
     hash TEXT NOT NULL,
     frame TEXT NOT NULL,
     operatorId TEXT NOT NULL,
     name TEXT NOT NULL,
     recoveryFp TEXT NOT NULL,
     storedAt INTEGER NOT NULL
   );
CREATE TABLE recovery_rotations(
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     hash TEXT UNIQUE NOT NULL,
     frame TEXT NOT NULL,
     fromFp TEXT NOT NULL,
     toFp TEXT NOT NULL,
     storedAt INTEGER NOT NULL
   );
CREATE TABLE signup_codes(
     emailHash TEXT PRIMARY KEY,
     codeMac TEXT NOT NULL,
     expiresAt INTEGER NOT NULL,
     attempts INTEGER NOT NULL DEFAULT 0
   );
CREATE TABLE signup_tickets(
     ticketHash TEXT PRIMARY KEY,
     emailHash TEXT NOT NULL,
     expiresAt INTEGER NOT NULL,
     usedAt INTEGER
   );
CREATE TABLE recovery_requests(
     requestId TEXT PRIMARY KEY,
     userId TEXT NOT NULL REFERENCES users(userId),
     emailHash TEXT NOT NULL,
     rPub TEXT NOT NULL,
     pollHash TEXT NOT NULL,
     platform TEXT NOT NULL,
     codeMac TEXT,
     codeExpiresAt INTEGER,
     attempts INTEGER NOT NULL DEFAULT 0,
     state TEXT NOT NULL CHECK(state IN ('unverified','verified','vetoed','fulfilled')),
     createdAt INTEGER NOT NULL,
     verifiedAt INTEGER,
     holdEndsAt INTEGER,
     sealed TEXT
   );
CREATE INDEX idx_recovery_requests_user ON recovery_requests(userId);
CREATE TABLE mail_outbox(
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     template TEXT NOT NULL,
     recipient TEXT NOT NULL,
     subject TEXT NOT NULL,
     text TEXT NOT NULL,
     html TEXT NOT NULL,
     createdAt INTEGER NOT NULL,
     attempts INTEGER NOT NULL DEFAULT 0,
     nextAttemptAt INTEGER NOT NULL,
     lastErrorClass TEXT,
     discardAt INTEGER NOT NULL
   );
CREATE TABLE audit(
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     at INTEGER NOT NULL,
     type TEXT NOT NULL,
     userId TEXT,
     deviceId TEXT,
     ip TEXT,
     meta TEXT
   );
CREATE INDEX idx_audit_user ON audit(userId);
CREATE INDEX idx_audit_type_at ON audit(type, at);
CREATE TABLE policies(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL);
INSERT INTO meta(key,value) VALUES('baseline','onboarding-trust-1');
INSERT INTO meta(key,value) VALUES('oldestRetainedRev','0');
