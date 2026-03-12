import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UsersService } from 'src/users/users.service';
import { RequestContext } from '@/logger/request-context';
import { TokenRevocationService } from '@/security/token-revocation/token-revocation.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
    private tokenRevocationService: TokenRevocationService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('keys.publicKey'),
      algorithms: ['RS256'],
    });
  }

  async validate(payload: { sub: string; email: string; roleId?: string; jti?: string }) {
    // --- JTI revocation check ---
    // O(1) Redis lookup. If the JTI is in the revocation list (logout, password-change,
    // session eviction), the token is immediately rejected — even within the 15-min TTL.
    // Fails OPEN if Redis is unavailable (see TokenRevocationService for rationale).
    if (payload.jti) {
      const revoked = await this.tokenRevocationService.isRevoked(payload.jti);
      if (revoked) {
        throw new UnauthorizedException('Token has been revoked');
      }
    }

    // --- User state validation ---
    // Always reload from DB — do NOT trust roleId from the JWT claim.
    // If an admin changes a user's role, the JWT claim becomes stale.
    // The DB lookup ensures the current role is always used for RBAC checks.
    const user = await this.usersService.findOne(payload.email);

    if (!user || !user.isActive) {
      throw new UnauthorizedException('Invalid token');
    }

    const now = new Date();
    if (user.lockedUntil && user.lockedUntil > now) {
      throw new UnauthorizedException('Account is locked. Try again later.');
    }

    RequestContext.setUser(user.id);

    // Strip password hash — must NEVER be present in req.user
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: _password, ...safeUser } = user;
    return safeUser;
  }
}
