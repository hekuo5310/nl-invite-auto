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
