import { FastifyInstance } from 'fastify';
import { requireAdmin } from '../middleware/requireAdmin';
import { prisma } from '../db';
export async function userRoutes(fastify: FastifyInstance) {

  fastify.get('/users', { preHandler: [requireAdmin] }, async (req, reply) => {
    const users = await prisma.user.findMany({
      select: { id: true, username: true, role: true, createdAt: true }
    });
    reply.send(users);
  });
}
