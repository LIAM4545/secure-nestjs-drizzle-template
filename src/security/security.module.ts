import { Global, Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { TokenRevocationService } from './token-revocation/token-revocation.service';
import { SuspiciousActivityService } from './detection/suspicious-activity.service';

/**
 * SecurityModule is @Global — TokenRevocationService and SuspiciousActivityService
 * are available to any module (AuthModule, JwtStrategy, etc.) via DI without
 * explicit imports. CacheModule provides CACHE_MANAGER for both services.
 *
 * Must be imported in AppModule before AuthModule.
 */
@Global()
@Module({
  imports: [CacheModule.register()],
  providers: [TokenRevocationService, SuspiciousActivityService],
  exports: [TokenRevocationService, SuspiciousActivityService],
})
export class SecurityModule {}
