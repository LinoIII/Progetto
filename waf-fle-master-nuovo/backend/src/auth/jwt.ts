import { FastifyInstance } from 'fastify';

export async function signUserToken(
  fastify: FastifyInstance,
  user: { id: string; username: string; role: string }
) {
  return fastify.jwt.sign({
    sub: user.id,
    username: user.username,
    role: user.role
  });
}
