import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { verifyPassword, hashPassword } from './hash';
import { signUserToken } from './jwt';
import { requireAdmin } from '../middleware/requireAdmin';
import { requireAuth } from '../middleware/requireAuth';
import { validateBody } from '../utils/validate';
import { prisma } from '../db';
import { ENV } from '../env';

export async function authRoutes(fastify: FastifyInstance) {

  // login
  fastify.post('/auth/login', async (req, reply) => {
    const body = validateBody(req, z.object({
      username: z.string().min(1),
      password: z.string().min(1)
    }));

    const user = await prisma.user.findUnique({
      where: { username: body.username }
    });

    if (!user) {
      return reply.code(401).send({ error: 'Invalid credentials' });
    }

    const ok = await verifyPassword(user.password, body.password);
    if (!ok) {
      return reply.code(401).send({ error: 'Invalid credentials' });
    }

    const token = await signUserToken(fastify, {
      id: user.id,
      username: user.username,
      role: user.role
    });

    // HttpOnly cookie per ridurre rischio XSS -> session hijack
    reply
      .setCookie('auth', token, {
        httpOnly: true,
        secure: ENV.NODE_ENV === 'production', // secure solo in produzione

        sameSite: 'strict',

        path: '/'

      })

      .code(200)

      .send({ token }); // anche nel body se vuoi usarlo da client API

  });

 

  // logout

  fastify.post('/auth/logout', { preHandler: [requireAuth] }, async (req, reply) => {

    reply

      .clearCookie('auth', { path: '/' })

      .code(200)

      .send({ message: 'Logged out' });
  });

  // register nuovo utente (solo admin)
  fastify.post('/auth/register', { preHandler: [requireAdmin] }, async (req, reply) => {
    const body = validateBody(req, z.object({
      username: z.string().min(3),
      password: z.string().min(8),
      role: z.enum(['ADMIN','ANALYST']).default('ANALYST')
    }));

    const hashed = await hashPassword(body.password);

    const newUser = await prisma.user.create({
      data: {
        username: body.username,
        password: hashed,
        role: body.role
      },
      select: { id: true, username: true, role: true, createdAt: true }
    });

    reply.code(201).send(newUser);
  });
  // cambio password (utente autenticato)

  fastify.post('/auth/change-password', { preHandler: [requireAuth] }, async (req, reply) => {

    const body = validateBody(req, z.object({

      currentPassword: z.string().min(1),

      newPassword: z.string().min(8)

    }));

 

    const userId = (req.user as any).sub;

 

    const user = await prisma.user.findUnique({

      where: { id: userId }

    });

 

    if (!user) {

      return reply.code(404).send({ error: 'User not found' });

    }

 

    const ok = await verifyPassword(user.password, body.currentPassword);

    if (!ok) {

      return reply.code(401).send({ error: 'Current password is incorrect' });

    }

 

    const hashed = await hashPassword(body.newPassword);

 

    await prisma.user.update({

      where: { id: userId },

      data: { password: hashed }

    });

 

    reply.code(200).send({ message: 'Password changed successfully' });

  });
}

