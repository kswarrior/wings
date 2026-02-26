import { execSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import logger from "../../utils/logger";

export interface SftpCredential {
  username: string;
  password: string;
  host: string;
  port: number;
  directory: string;
  expiresAt: number;
}

interface ActiveSession {
  containerId: string;
  username: string;
  password: string;
  expiresAt: number;
  timer: NodeJS.Timeout;
}

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const SFTP_SSH_PORT = parseInt(process.env.SFTP_PORT || "22", 10);
const SFTP_USER_PREFIX = "alsftp_";
const VOLUMES_DIR = path.resolve("volumes");
const SSHD_CONFIG = "/etc/ssh/sshd_config";
const AIRLINK_MARKER = "# AirLink-SFTP-BEGIN";
const AIRLINK_END = "# AirLink-SFTP-END";

const activeSessions = new Map<string, ActiveSession>();

function sanitizeContainerId(id: string): boolean {
  return /^[a-zA-Z0-9_-]{1,64}$/.test(id);
}

function generateUsername(containerId: string): string {
  const hash = crypto
    .createHash("sha256")
    .update(containerId + Date.now().toString())
    .digest("hex")
    .substring(0, 8);
  return `${SFTP_USER_PREFIX}${hash}`;
}

function generatePassword(): string {
  return crypto.randomBytes(24).toString("base64url");
}

function execSafe(cmd: string): void {
  try {
    execSync(cmd, { stdio: "pipe" });
  } catch (err: any) {
    throw new Error(`Command failed: ${cmd}\n${err.stderr?.toString() || err.message}`);
  }
}

function reloadSshd(): void {
  try {
    execSync("systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || true", { stdio: "pipe" });
  } catch {
    // best effort
  }
}

function readSshdConfig(): string {
  try {
    return fs.readFileSync(SSHD_CONFIG, "utf-8");
  } catch (err) {
    logger.error("Cannot read sshd_config", err);
    throw new Error("Cannot read /etc/ssh/sshd_config");
  }
}

function writeSshdConfig(content: string): void {
  fs.writeFileSync(SSHD_CONFIG, content, "utf-8");
  reloadSshd();
}

// Extracts the managed block between our markers, returns the user match blocks inside it
function parseManagedBlock(config: string): { before: string; block: string; after: string } {
  const start = config.indexOf(AIRLINK_MARKER);
  const end = config.indexOf(AIRLINK_END);

  if (start === -1 || end === -1) {
    return { before: config, block: "", after: "" };
  }

  return {
    before: config.substring(0, start),
    block: config.substring(start + AIRLINK_MARKER.length, end),
    after: config.substring(end + AIRLINK_END.length),
  };
}

function buildUserMatchBlock(username: string, chrootDir: string): string {
  return `
Match User ${username}
    ChrootDirectory ${chrootDir}
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    AllowAgentForwarding no
`;
}

function addUserToSshdConfig(username: string, chrootDir: string): void {
  let config = readSshdConfig();

  // Ensure sftp subsystem is set to internal-sftp
  if (!config.includes("Subsystem sftp internal-sftp")) {
    config = config.replace(/^Subsystem\s+sftp\s+.+$/m, "");
    config += "\nSubsystem sftp internal-sftp\n";
  }

  const { before, block, after } = parseManagedBlock(config);
  const newBlock = block + buildUserMatchBlock(username, chrootDir);
  const newConfig = `${before}${AIRLINK_MARKER}${newBlock}${AIRLINK_END}${after}`;

  writeSshdConfig(newConfig);
}

function removeUserFromSshdConfig(username: string): void {
  const config = readSshdConfig();
  const { before, block, after } = parseManagedBlock(config);

  if (!block) return;

  // Remove the Match User block for this specific user
  const userBlockRegex = new RegExp(
    `\nMatch User ${username}\n(?:    [^\n]+\n)*`,
    "g"
  );
  const newBlock = block.replace(userBlockRegex, "");
  const newConfig = `${before}${AIRLINK_MARKER}${newBlock}${AIRLINK_END}${after}`;

  writeSshdConfig(newConfig);
}

async function createSystemUser(username: string, password: string, chrootDir: string): Promise<void> {
  // chroot dir must be root:root 755 — sshd requirement
  execSafe(`chown root:root ${chrootDir}`);
  execSafe(`chmod 755 ${chrootDir}`);

  // User home is / inside their chroot (which is the volume root)
  execSafe(`useradd -M -s /usr/sbin/nologin -d / ${username}`);
  execSafe(`echo '${username}:${password.replace(/'/g, "'\\''")}' | chpasswd`);

  addUserToSshdConfig(username, chrootDir);
}

async function removeSystemUser(username: string): Promise<void> {
  try {
    execSync(`userdel -f ${username} 2>/dev/null || true`, { stdio: "pipe" });
  } catch {
    // ignore
  }
  removeUserFromSshdConfig(username);
}

function scheduleExpiry(sessionKey: string, ttl: number): NodeJS.Timeout {
  return setTimeout(async () => {
    await revokeCredential(sessionKey);
  }, ttl);
}

export async function generateCredential(containerId: string): Promise<SftpCredential> {
  if (!sanitizeContainerId(containerId)) {
    throw new Error("Invalid container ID");
  }

  const chrootDir = path.join(VOLUMES_DIR, containerId);

  if (!fs.existsSync(chrootDir)) {
    throw new Error(`Volume for container ${containerId} does not exist`);
  }

  const existingKey = `container:${containerId}`;
  if (activeSessions.has(existingKey)) {
    await revokeCredential(existingKey);
  }

  const username = generateUsername(containerId);
  const password = generatePassword();
  const expiresAt = Date.now() + SESSION_TTL_MS;

  await createSystemUser(username, password, chrootDir);

  const timer = scheduleExpiry(existingKey, SESSION_TTL_MS);

  activeSessions.set(existingKey, {
    containerId,
    username,
    password,
    expiresAt,
    timer,
  });

  const host = process.env.remote || "127.0.0.1";

  logger.info(`SFTP credential created for container ${containerId}: user=${username}`);

  return {
    username,
    password,
    host,
    port: SFTP_SSH_PORT,
    directory: "/",
    expiresAt,
  };
}

export async function revokeCredential(sessionKey: string): Promise<void> {
  const session = activeSessions.get(sessionKey);
  if (!session) return;

  clearTimeout(session.timer);
  activeSessions.delete(sessionKey);

  await removeSystemUser(session.username);

  logger.info(`SFTP credential revoked for container ${session.containerId}: user=${session.username}`);
}

export async function revokeCredentialForContainer(containerId: string): Promise<void> {
  await revokeCredential(`container:${containerId}`);
}

export function getActiveSessionCount(): number {
  return activeSessions.size;
}

export async function cleanupExpiredSessions(): Promise<void> {
  const now = Date.now();
  for (const [key, session] of activeSessions.entries()) {
    if (session.expiresAt <= now) {
      await revokeCredential(key);
    }
  }
}

setInterval(cleanupExpiredSessions, 60 * 60 * 1000);
