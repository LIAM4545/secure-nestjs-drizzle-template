import { Module } from '@nestjs/common';
import { SuspiciousActivityService } from './suspicious-activity.service';
import { AuditModule } from '@/modules/audit/audit.module';

@Module({
  imports: [AuditModule],
  providers: [SuspiciousActivityService],
  exports: [SuspiciousActivityService],
})
export class SuspiciousActivityModule {}
