-- 每天的申请锁：不论 AI 拒绝、上游失败或成功，均占用当天名额。
CREATE TABLE IF NOT EXISTS daily_locks (
  subject_kind TEXT NOT NULL CHECK(subject_kind IN ('ip', 'fingerprint')),
  subject_hash TEXT NOT NULL,
  day TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (subject_kind, subject_hash, day)
);

-- 成功后永久锁定。哈希值不可反推出 IP 或设备指纹。
CREATE TABLE IF NOT EXISTS permanent_success_locks (
  subject_kind TEXT NOT NULL CHECK(subject_kind IN ('ip', 'fingerprint')),
  subject_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (subject_kind, subject_hash)
);

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  ip_hash TEXT NOT NULL,
  fingerprint_hash TEXT NOT NULL,
  application_text TEXT NOT NULL,
  ai_approved INTEGER,
  ai_reason TEXT,
  status TEXT NOT NULL CHECK(status IN ('pending', 'rejected', 'upstream_failed', 'succeeded')),
  invite_key TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS applications_created_at ON applications(created_at);

-- 每日北京时间 08:00 创建的一张邀请码；所有当天获批者共享其链接。
CREATE TABLE IF NOT EXISTS daily_invites (
  day TEXT PRIMARY KEY,
  invite_key TEXT NOT NULL,
  invite_link TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invite_claims (
  day TEXT NOT NULL REFERENCES daily_invites(day),
  application_id TEXT NOT NULL UNIQUE REFERENCES applications(id),
  claimed_at TEXT NOT NULL,
  PRIMARY KEY (day, application_id)
);

-- 数据库层硬限制每天最多三次发放，避免并发申请突破额度。
CREATE TRIGGER IF NOT EXISTS limit_daily_invite_claims
BEFORE INSERT ON invite_claims
WHEN (SELECT COUNT(*) FROM invite_claims WHERE day = NEW.day) >= 3
BEGIN
  SELECT RAISE(ABORT, 'daily invite quota exhausted');
END;

-- 新模式：每天创建 3 个单次邀请码，按 fetched_at 先进先出发放。
CREATE TABLE IF NOT EXISTS pool_generation_slots (
  source_day TEXT NOT NULL,
  slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 3),
  state TEXT NOT NULL CHECK(state IN ('pending', 'creating', 'ready')),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (source_day, slot)
);

CREATE TABLE IF NOT EXISTS invite_pool (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_day TEXT NOT NULL,
  slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 3),
  invite_key TEXT NOT NULL UNIQUE,
  invite_link TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  application_id TEXT UNIQUE REFERENCES applications(id),
  claimed_at TEXT,
  UNIQUE(source_day, slot)
);

CREATE INDEX IF NOT EXISTS invite_pool_fifo ON invite_pool(application_id, fetched_at, id);

-- 最新的 NodeLoc 会话；敏感内容由 Worker 在写入前加密。
CREATE TABLE IF NOT EXISTS nodeloc_session (
  id TEXT PRIMARY KEY CHECK(id = 'active'),
  encrypted_cookie TEXT NOT NULL,
  encrypted_csrf_token TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
