import { execSync, exec } from "child_process";
import { promisify } from "util";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import logger from "../../utils/logger";

const execAsync = promisify(exec);

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
  volumePath: string;
  expiresAt: number;
  timer: NodeJS.Timeout;
}

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const SFTP_SSH_PORT = parseInt(process.env.SFTP_PORT || "2222", 10);
const SFTP_USER_PREFIX = "alsftp_";

const activeSessions = new Map<string, ActiveSession>();

function getVolumePathForContainer(containerId: string): string {
  return path.resolve(`volumes/${containerId}`);
}

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

async function sshd_configured(): Promise<boolean> {
  try {
    const sshdConfig = fs.readFileSync("/etc/ssh/sshd_config", "utf-8");
    return sshdConfig.includes("Subsystem sftp internal-sftp") &&
           sshdConfig.includes("ChrootDirectory");
  } catch {
    return false;
  }
}

async function ensureSshdConfigured(): Promise<void> {
  const configPath = "/etc/ssh/sshd_config";
  const matchBlock = `

# AirLink SFTP managed block - do not edit manually
Match Group airlinksftp
    ChrootDirectory %h
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    AllowAgentForwarding no
`;

  let config = "";
  try {
    config = fs.readFileSync(configPath, "utf-8");
  } catch {
    logger.error("Cannot read sshd_config");
    throw new Error("Cannot read /etc/ssh/sshd_config");
  }

  let changed = false;

  if (!config.includes("Subsystem sftp internal-sftp")) {
    config = config.replace(/^Subsystem\s+sftp\s+.+$/m, "");
    config += "\nSubsystem sftp internal-sftp\n";
    changed = true;
  }

  if (!config.includes("airlinksftp")) {
    config += matchBlock;
    changed = true;
  }

  if (changed) {
    fs.writeFileSync(configPath, config, "utf-8");
    try {
      execSync("systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || true", { stdio: "pipe" });
    } catch {
      // best effort reload
    }
    logger.info("sshd_config updated for SFTP chroot support");
  }

  // Ensure the airlinksftp group exists
  try {
    execSync("getent group airlinksftp", { stdio: "pipe" });
  } catch {
    execSync("groupadd airlinksftp", { stdio: "pipe" });
    logger.info("Created airlinksftp group");
  }
}

function buildChrootDir(username: string, volumePath: string): string {
  // The chroot dir must be owned by root with no write permission for anyone else
  // We put a subdirectory inside called "files" that is owned by the sftp user
  return path.resolve(`/tmp/alsftp_chroot/${username}`);
}

async function setupChrootStructure(
  username: string,
  volumePath: string
): Promise<string> {
  const chrootBase = `/tmp/alsftp_chroot/${username}`;
  const filesDir = `${chrootBase}/files`;

  fs.mkdirSync(chrootBase, { recursive: true });
  fs.mkdirSync(filesDir, { recursive: true });

  // chroot root must be owned by root:root, mode 755 - SSH requirement
  execSafe(`chown root:root ${chrootBase}`);
  execSafe(`chmod 755 ${chrootBase}`);

  // Bind mount the actual volume directory
  if (!fs.existsSync(volumePath)) {
    fs.mkdirSync(volumePath, { recursive: true });
  }

  // Check if already mounted
  try {
    const mounts = fs.readFileSync("/proc/mounts", "utf-8");
    if (!mounts.includes(filesDir)) {
      execSafe(`mount --bind ${volumePath} ${filesDir}`);
    }
  } catch {
    execSafe(`mount --bind ${volumePath} ${filesDir}`);
  }

  // The files directory should be owned by the sftp user
  execSafe(`chown ${username}:airlinksftp ${filesDir}`);
  execSafe(`chmod 750 ${filesDir}`);

  return chrootBase;
}

async function teardownChrootStructure(username: string): Promise<void> {
  const chrootBase = `/tmp/alsftp_chroot/${username}`;
  const filesDir = `${chrootBase}/files`;

  try {
    execSync(`umount ${filesDir} 2>/dev/null || true`, { stdio: "pipe" });
  } catch {
    // ignore
  }

  try {
    fs.rmSync(chrootBase, { recursive: true, force: true });
  } catch {
    // ignore
  }
}

async function createSystemUser(username: string, password: string, chrootBase: string): Promise<void> {
  // Create user with no login shell, no home dir creation initially
  execSafe(`useradd -M -s /usr/sbin/nologin -g airlinksftp -d /files ${username}`);

  // Set password
  execSafe(`echo '${username}:${password.replace(/'/g, "'\\''")}' | chpasswd`);
}

async function removeSystemUser(username: string): Promise<void> {
  try {
    execSync(`userdel -f ${username} 2>/dev/null || true`, { stdio: "pipe" });
  } catch {
    // ignore
  }
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

  const volumePath = getVolumePathForContainer(containerId);

  if (!fs.existsSync(volumePath)) {
    throw new Error(`Volume for container ${containerId} does not exist`);
  }

  // Revoke any existing session for this container
  const existingKey = `container:${containerId}`;
  if (activeSessions.has(existingKey)) {
    await revokeCredential(existingKey);
  }

  await ensureSshdConfigured();

  const username = generateUsername(containerId);
  const password = generatePassword();
  const expiresAt = Date.now() + SESSION_TTL_MS;

  const chrootBase = await setupChrootStructure(username, volumePath);
  await createSystemUser(username, password, chrootBase);

  const timer = scheduleExpiry(existingKey, SESSION_TTL_MS);

  activeSessions.set(existingKey, {
    containerId,
    username,
    password,
    volumePath,
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
    directory: "/files",
    expiresAt,
  };
}

export async function revokeCredential(sessionKey: string): Promise<void> {
  const session = activeSessions.get(sessionKey);
  if (!session) return;

  clearTimeout(session.timer);
  activeSessions.delete(sessionKey);

  await removeSystemUser(session.username);
  await teardownChrootStructure(session.username);

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

// Periodic cleanup every hour
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);
