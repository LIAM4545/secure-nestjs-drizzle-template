import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { and, asc, count, eq, inArray, isNull } from 'drizzle-orm';
import { createHash, randomUUID, timingSafeEqual } from 'crypto';
import * as argon2 from 'argon2';
import { compare as bcryptCompare } from 'bcryptjs';
import { UsersService } from 'src/users/users.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshDto } from './dto/refresh.dto';
import { DatabaseService } from '@/database/database.service';
import { sessions, Session } from '@/database/schema/sessions.schema';
import { users, User } from '@/database/schema/users.schema';
import { AuditLogService } from '@/modules/audit/audit-log.service';
import { TokenRevocationService } from '@/security/token-revocation/token-revocation.service';
import { SuspiciousActivityService } from '@/security/detection/suspicious-activity.service';

const ACCESS_TOKEN_EXPIRES = '15m';
const REFRESH_TOKEN_EXPIRES = '7d';

/** Maximum concurrent active sessions per user. Oldest is evicted when exceeded. */
const MAX_SESSIONS_PER_USER = 10;

const ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MiB
  timeCost: 3,
  parallelism: 4,
};

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private jwtService: JwtService,
    private usersService: UsersService,
    private auditLogService: AuditLogService,
    private dbService: DatabaseService,
    private tokenRevocationService: TokenRevocationService,
    private suspiciousActivityService: SuspiciousActivityService,
  ) {}

  private get db() {
    return this.dbService.db;
  }

  // ---------------------------------------------------------------------------
  // Password verification
  // ---------------------------------------------------------------------------

  /**
   * Verify plaintext against a stored hash.
   * Supports both Argon2id (new) and bcrypt (legacy migration path).
   */
  private async verifyPassword(
    plaintext: string,
    stored: string,
  ): Promise<{ valid: boolean; needsRehash: boolean }> {
    if (stored.startsWith('$argon2')) {
      const valid = await argon2.verify(stored, plaintext);
      return { valid, needsRehash: false };
    }
    const valid = await bcryptCompare(plaintext, stored);
    return { valid, needsRehash: valid }; // bcrypt: rehash on success
  }

  // ---------------------------------------------------------------------------
  // Device fingerprinting
  // ---------------------------------------------------------------------------

  private deviceFingerprint(userAgent: string | undefined, ip: string | undefined): string {
    return createHash('sha256')
      .update(`${userAgent ?? ''}|${ip ?? ''}`)
      .digest('hex')
      .slice(0, 32);
  }

  // ---------------------------------------------------------------------------
  // Session family graph (for reuse detection / forensics)
  // ---------------------------------------------------------------------------

  private hashRefreshToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');
    if (bufA.length !== bufB.length) return false;
    try {
      return timingSafeEqual(bufA, bufB);
    } catch {
      return false;
    }
  }

  private async getSessionFamilyIds(session: Session): Promise<string[]> {
    const ids: string[] = [session.id];
    const visited = new Set<string>([session.id]);

    let currentId: string | null = session.rotatedFromSessionId;
    while (currentId) {
      const [parent] = await this.db
        .select()
        .from(sessions)
        .where(eq(sessions.id, currentId))
        .limit(1);
      if (!parent || visited.has(parent.id)) break;
      ids.push(parent.id);
      visited.add(parent.id);
      currentId = parent.rotatedFromSessionId;
    }

    let toVisit = [...ids];
    while (toVisit.length > 0) {
      const children = await this.db
        .select()
        .from(sessions)
        .where(inArray(sessions.rotatedFromSessionId, toVisit));
      toVisit = [];
      for (const c of children) {
        if (!visited.has(c.id)) {
          visited.add(c.id);
          ids.push(c.id);
          toVisit.push(c.id);
        }
      }
    }

    return ids;
  }

  private async revokeSessionFamilyAndLogReuse(
    reusedSession: Session,
    ip?: string,
    userAgent?: string,
  ): Promise<void> {
    const userId = reusedSession.userId;
    const sessionFamilyIds = await this.getSessionFamilyIds(reusedSession);

    // Revoke ALL sessions for this user
    const revokedSessions = await this.db
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
      .returning({ id: sessions.id, accessTokenJti: sessions.accessTokenJti });

    // Also add all access token JTIs to the revocation list
    const jtis = revokedSessions
      .map((s) => s.accessTokenJti)
      .filter((j): j is string => !!j);

    if (jtis.length > 0) {
      await this.tokenRevocationService
        .revokeMany(jtis, TokenRevocationService.ACCESS_TOKEN_TTL_SECONDS)
        .catch((err: Error) =>
          this.logger.error(`JTI revocation failed during reuse cleanup: ${err.message}`),
        );
    }

    this.logger.warn(
      `Refresh token reuse detected for user ${userId}. Revoked ${revokedSessions.length} sessions.`,
    );

    await this.auditLogService.log({
      action: 'auth.refresh_token_reuse_detected',
      entityType: 'Session',
      entityId: reusedSession.id,
      actorUserId: userId,
      metadata: { sessionFamilyIds, revokedCount: revokedSessions.length },
      ip: ip ?? undefined,
      userAgent: userAgent ?? undefined,
    });
  }

  // ---------------------------------------------------------------------------
  // Session count enforcement
  // ---------------------------------------------------------------------------

  /**
   * If the user already has MAX_SESSIONS_PER_USER active sessions, revoke the
   * oldest ones to stay within the limit. This prevents session table bloat
   * and limits the blast radius if an account is repeatedly compromised.
   */
  private async enforceSessionLimit(userId: string): Promise<void> {
    const activeSessions = await this.db
      .select({ id: sessions.id, accessTokenJti: sessions.accessTokenJti })
      .from(sessions)
      .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
      .orderBy(asc(sessions.createdAt));

    if (activeSessions.length < MAX_SESSIONS_PER_USER) return;

    // Evict oldest sessions to make room for the new one
    const toEvict = activeSessions.slice(0, activeSessions.length - MAX_SESSIONS_PER_USER + 1);
    const idsToEvict = toEvict.map((s) => s.id);
    const jtisToRevoke = toEvict.map((s) => s.accessTokenJti).filter((j): j is string => !!j);

    await this.db
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(inArray(sessions.id, idsToEvict));

    if (jtisToRevoke.length > 0) {
      await this.tokenRevocationService
        .revokeMany(jtisToRevoke, TokenRevocationService.ACCESS_TOKEN_TTL_SECONDS)
        .catch(() => undefined); // non-critical: token will expire anyway
    }

    this.logger.log(`Evicted ${toEvict.length} oldest sessions for user ${userId} (limit: ${MAX_SESSIONS_PER_USER})`);
  }

  // ---------------------------------------------------------------------------
  // Public auth flows
  // ---------------------------------------------------------------------------

  async login(
    dto: LoginDto,
    ip?: string,
    userAgent?: string,
  ): Promise<{ email: string; access_token: string; refresh_token: string }> {
    // --- IP blocklist check (credential stuffing protection) ---
    if (ip && (await this.suspiciousActivityService.isIpBlocked(ip))) {
      throw new HttpException(
        'Too many failed attempts from this IP. Please try again later.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const user = await this.usersService.findOne(dto.email);

    // Uniform error for all negative paths — prevents user enumeration
    if (!user || !user.isActive) {
      // Still record the failed attempt to detect credential stuffing
      if (ip) {
        await this.suspiciousActivityService.recordFailedAttempt(ip, dto.email);
      }
      throw new UnauthorizedException('Invalid credentials');
    }

    const now = new Date();
    if (user.lockedUntil && user.lockedUntil > now) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const { valid, needsRehash } = await this.verifyPassword(dto.password, user.password);

    if (!valid) {
      // Record for both per-account lockout AND cross-account IP detection
      const [failResult] = await Promise.all([
        this.usersService.recordFailedLogin(user.id),
        ip ? this.suspiciousActivityService.recordFailedAttempt(ip, dto.email) : Promise.resolve(false),
      ]);

      if (failResult.lockedUntil) {
        await this.auditLogService.log({
          action: 'auth.account.locked',
          entityType: 'User',
          entityId: user.id,
          actorUserId: null,
          metadata: { failedAttempts: failResult.failedLoginAttempts },
          ip: ip ?? undefined,
          userAgent: userAgent ?? undefined,
        });
      }

      throw new UnauthorizedException('Invalid credentials');
    }

    await this.usersService.resetFailedLogin(user.id);

    // Transparent Argon2 migration: rehash bcrypt hashes on successful login
    if (needsRehash) {
      argon2
        .hash(dto.password, ARGON2_OPTIONS)
        .then((newHash) => this.usersService.updatePassword(user.id, newHash))
        .catch((err: Error) =>
          this.logger.warn(`Argon2 rehash failed for user ${user.id}: ${err.message}`),
        );
    }

    return this.createTokensAndSession(user, ip, userAgent);
  }

  async refresh(
    dto: RefreshDto,
    ip?: string,
    userAgent?: string,
  ): Promise<{ email: string; access_token: string; refresh_token: string }> {
    const token = dto.refresh_token;

    let payload: { sub: string; email: string; roleId?: string; exp: number };
    try {
      payload = this.jwtService.verify(token, { algorithms: ['RS256'] });
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const tokenHash = this.hashRefreshToken(token);

    const [sessionWithUser] = await this.db.query.sessions.findMany({
      with: { user: true },
      where: eq(sessions.refreshTokenHash, tokenHash),
      limit: 1,
    });

    if (!sessionWithUser || !this.constantTimeCompare(tokenHash, sessionWithUser.refreshTokenHash)) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const now = new Date();
    if (sessionWithUser.revokedAt) {
      await this.revokeSessionFamilyAndLogReuse(sessionWithUser, ip, userAgent);
      throw new UnauthorizedException(
        'Refresh token reuse detected. All sessions have been revoked.',
      );
    }

    if (sessionWithUser.expiresAt < now) {
      throw new UnauthorizedException('Refresh token expired');
    }

    const user = sessionWithUser.user;
    if (!user.isActive) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    return this.rotateSession(sessionWithUser, user, ip, userAgent);
  }

  async logout(userId: string, refreshToken: string): Promise<void> {
    const tokenHash = this.hashRefreshToken(refreshToken);

    // Find the session to retrieve its access token JTI
    const [session] = await this.db
      .select({ id: sessions.id, accessTokenJti: sessions.accessTokenJti })
      .from(sessions)
      .where(
        and(
          eq(sessions.userId, userId),
          eq(sessions.refreshTokenHash, tokenHash),
          isNull(sessions.revokedAt),
        ),
      )
      .limit(1);

    if (!session) return; // already revoked or doesn't belong to user — silently ignore

    // Revoke the DB session
    await this.db
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(eq(sessions.id, session.id));

    // Immediately invalidate the associated access token via JTI
    if (session.accessTokenJti) {
      await this.tokenRevocationService
        .revokeToken(
          session.accessTokenJti,
          TokenRevocationService.ACCESS_TOKEN_TTL_SECONDS,
        )
        .catch((err: Error) =>
          this.logger.warn(`JTI revocation failed on logout: ${err.message}`),
        );
    }
  }

  // ---------------------------------------------------------------------------
  // Token / session creation
  // ---------------------------------------------------------------------------

  private async createTokensAndSession(
    user: User,
    ip?: string,
    userAgent?: string,
  ): Promise<{ email: string; access_token: string; refresh_token: string }> {
    // Enforce session count limit before creating a new session
    await this.enforceSessionLimit(user.id);

    const jti = randomUUID(); // unique ID for this access token — used for revocation
    const tokenPayload = { sub: user.id, email: user.email, roleId: user.roleId, jti };

    const accessToken = this.jwtService.sign(tokenPayload, {
      expiresIn: ACCESS_TOKEN_EXPIRES,
      algorithm: 'RS256',
    });

    const refreshToken = this.jwtService.sign(
      { sub: user.id, email: user.email, roleId: user.roleId },
      { expiresIn: REFRESH_TOKEN_EXPIRES, algorithm: 'RS256' },
    );

    const refreshTokenHash = this.hashRefreshToken(refreshToken);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.db.insert(sessions).values({
      userId: user.id,
      refreshTokenHash,
      accessTokenJti: jti,
      deviceFingerprint: this.deviceFingerprint(userAgent, ip),
      ip: ip ?? null,
      userAgent: userAgent ?? null,
      expiresAt,
    });

    return {
      email: user.email,
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  private async rotateSession(
    oldSession: Session,
    user: User,
    ip?: string,
    userAgent?: string,
  ): Promise<{ email: string; access_token: string; refresh_token: string }> {
    // Revoke the old session
    await this.db
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(eq(sessions.id, oldSession.id));

    // Revoke the old access token JTI immediately
    if (oldSession.accessTokenJti) {
      await this.tokenRevocationService
        .revokeToken(
          oldSession.accessTokenJti,
          TokenRevocationService.ACCESS_TOKEN_TTL_SECONDS,
        )
        .catch(() => undefined); // non-critical: old token expires soon anyway
    }

    const jti = randomUUID();
    const tokenPayload = { sub: user.id, email: user.email, roleId: user.roleId, jti };

    const accessToken = this.jwtService.sign(tokenPayload, {
      expiresIn: ACCESS_TOKEN_EXPIRES,
      algorithm: 'RS256',
    });

    const refreshToken = this.jwtService.sign(
      { sub: user.id, email: user.email, roleId: user.roleId },
      { expiresIn: REFRESH_TOKEN_EXPIRES, algorithm: 'RS256' },
    );

    const refreshTokenHash = this.hashRefreshToken(refreshToken);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.db.insert(sessions).values({
      userId: user.id,
      refreshTokenHash,
      accessTokenJti: jti,
      deviceFingerprint: this.deviceFingerprint(userAgent, ip),
      ip: ip ?? null,
      userAgent: userAgent ?? null,
      expiresAt,
      rotatedFromSessionId: oldSession.id,
    });

    return {
      email: user.email,
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  // ---------------------------------------------------------------------------
  // Registration / password management
  // ---------------------------------------------------------------------------

  async register(dto: RegisterDto) {
    const existing = await this.usersService.findOne(dto.email);
    if (existing) {
      throw new ConflictException('User already exists');
    }

    const hashedPassword = await argon2.hash(dto.password, ARGON2_OPTIONS);
    const user = await this.usersService.create({
      email: dto.email,
      name: dto.name,
      password: hashedPassword,
    });

    return { message: 'User created with success', userId: user.id };
  }

  async changePassword(
    userId: string,
    newPassword: string,
    ip?: string,
    userAgent?: string,
  ): Promise<{ userId: string }> {
    const hashedPassword = await argon2.hash(newPassword, ARGON2_OPTIONS);
    await this.usersService.updatePassword(userId, hashedPassword);

    // Collect all active session JTIs before revoking — needed for access token revocation
    const activeSessions = await this.db
      .select({ id: sessions.id, accessTokenJti: sessions.accessTokenJti })
      .from(sessions)
      .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)));

    const jtis = activeSessions
      .map((s) => s.accessTokenJti)
      .filter((j): j is string => !!j);

    // Revoke all DB sessions
    const revoked = await this.db
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
      .returning({ id: sessions.id });

    // Revoke all associated access tokens immediately via JTI
    if (jtis.length > 0) {
      await this.tokenRevocationService
        .revokeMany(jtis, TokenRevocationService.ACCESS_TOKEN_TTL_SECONDS)
        .catch((err: Error) =>
          this.logger.error(`JTI revocation failed on password change: ${err.message}`),
        );
    }

    this.logger.log(
      `Password changed for user ${userId}. Revoked ${revoked.length} sessions and ${jtis.length} access tokens.`,
    );

    await this.auditLogService.log({
      action: 'auth.password.changed',
      entityType: 'User',
      entityId: userId,
      actorUserId: userId,
      metadata: { revokedSessions: revoked.length },
      ip: ip ?? undefined,
      userAgent: userAgent ?? undefined,
    });

    return { userId };
  }
}
