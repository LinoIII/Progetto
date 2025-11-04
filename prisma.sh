#!/bin/sh
# da eseguire dentro container api oppure con `docker compose run api sh`

set -e

npx prisma migrate deploy
npx prisma generate

node - << 'EOF'
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';

const prisma = new PrismaClient();

async function main() {
  const adminUser = process.env.INIT_ADMIN_USER || 'admin';
  const adminPass = process.env.INIT_ADMIN_PASS || 'ChangeMeNow!';

  const hash = await argon2.hash(adminPass, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1
  });

  const existing = await prisma.user.findUnique({ where: { username: adminUser }});
  if (!existing) {
    await prisma.user.create({
      data: {
        username: adminUser,
        password: hash,
        role: 'ADMIN'
      }
    });
    console.log('Admin creato:', adminUser);
  } else {
    console.log('Admin già esistente');
  }
}
main().then(()=>process.exit(0));
EOF
