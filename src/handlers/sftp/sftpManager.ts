import crypto from "crypto";
import path from "path";
import fs from "fs";
import logger from "../../utils/logger";
import { docker } from "../instances/utils";

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
  sftpContainerName: string;
  hostPort: number;
  expiresAt: number;
  timer: NodeJS.Timeout;
}

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const SFTP_IMAGE = "atmoz/sftp";
const SFTP_USER_PREFIX = "alsftp_";
const PORT_RANGE_START = 2200;
const PORT_RANGE_END = 2299;

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

function getUsedPorts(): Set<number> {
  const used = new Set<number>();
  for (const session of activeSessions.values()) {
    used.add(session.hostPort);
  }
  return used;
}

function allocatePort(): number {
  const used = getUsedPorts();
  for (let p = PORT_RANGE_START; p <= PORT_RANGE_END; p++) {
    if (!used.has(p)) return p;
  }
  throw new Error("No available SFTP ports in range");
}

async function pullSftpImage(): Promise<void> {
  try {
    await docker.getImage(SFTP_IMAGE).inspect();
  } catch {
    logger.info(`Pulling ${SFTP_IMAGE} image...`);
    await new Promise<void>((resolve, reject) => {
      docker.pull(SFTP_IMAGE, (err: any, stream: any) => {
        if (err) return reject(err);
        docker.modem.followProgress(stream, (err: any) => {
          if (err) return reject(err);
          resolve();
        });
      });
    });
  }
}

async function startSftpContainer(
  containerName: string,
  username: string,
  password: string,
  volumePath: string,
  hostPort: number
): Promise<void> {
  // atmoz/sftp expects: username:password:::directory
  // The directory after ::: is created inside /home/username and becomes the upload dir
  const userSpec = `${username}:${password}:::upload`;

  const container = await docker.createContainer({
    name: containerName,
    Image: SFTP_IMAGE,
    Cmd: [userSpec],
    HostConfig: {
      Binds: [`${volumePath}:/home/${username}/upload`],
      PortBindings: {
        "22/tcp": [{ HostPort: String(hostPort) }],
      },
      AutoRemove: true,
    },
  });

  await container.start();
}

async function stopSftpContainer(containerName: string): Promise<void> {
  try {
    const container = docker.getContainer(containerName);
    await container.stop({ t: 3 });
  } catch {
    // already stopped or removed
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

  const volumePath = path.resolve("volumes", containerId);

  if (!fs.existsSync(volumePath)) {
    throw new Error(`Volume for container ${containerId} does not exist`);
  }

  const existingKey = `container:${containerId}`;
  if (activeSessions.has(existingKey)) {
    await revokeCredential(existingKey);
  }

  await pullSftpImage();

  const username = generateUsername(containerId);
  const password = generatePassword();
  const hostPort = allocatePort();
  const sftpContainerName = `alsftp_${containerId}`;
  const expiresAt = Date.now() + SESSION_TTL_MS;

  await startSftpContainer(sftpContainerName, username, password, volumePath, hostPort);

  const timer = scheduleExpiry(existingKey, SESSION_TTL_MS);

  activeSessions.set(existingKey, {
    containerId,
    username,
    sftpContainerName,
    hostPort,
    expiresAt,
    timer,
  });

  const host = process.env.remote || "127.0.0.1";

  logger.info(`SFTP session started for container ${containerId}: user=${username} port=${hostPort}`);

  return {
    username,
    password,
    host,
    port: hostPort,
    directory: "/upload",
    expiresAt,
  };
}

export async function revokeCredential(sessionKey: string): Promise<void> {
  const session = activeSessions.get(sessionKey);
  if (!session) return;

  clearTimeout(session.timer);
  activeSessions.delete(sessionKey);

  await stopSftpContainer(session.sftpContainerName);

  logger.info(`SFTP session ended for container ${session.containerId}: user=${session.username}`);
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
