import { Module } from '@nestjs/common';
import { TokenRevocationService } from './token-revocation.service';

@Module({
  providers: [TokenRevocationService],
  exports: [TokenRevocationService],
})
export class TokenRevocationModule {}
