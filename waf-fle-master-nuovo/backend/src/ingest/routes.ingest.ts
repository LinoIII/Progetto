import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { ENV } from '../env';
import { prisma } from '../db';

// Schema di validazione della richiesta di ingest ModSecurity
const ingestSchema = z.object({
  sourceIp: z.string().ip(),
  destIp: z.string().ip().optional(),
  uri: z.string(),
  method: z.string(),
  status: z.number().int().optional(),
  wafAction: z.string(),           // "blocked", "allowed"
  ruleId: z.string().optional(),   // es "942100"
  ruleMessage: z.string().optional(),
  severity: z.string().optional(),
  headers: z.string().optional(),  // raw headers o JSON serializzato
  body: z.string().optional(),
  userAgent: z.string().optional(),
  occurredAt: z.string().datetime().optional()
});

export async function ingestRoutes(fastify: FastifyInstance) {
  fastify.post(
    '/ingest/modsec',
    async (req: FastifyRequest, reply: FastifyReply) => {
      //
      // 1. Autorizzazione con API key
      //
      const apiKeyHeader = req.headers['x-api-key'];
      if (apiKeyHeader !== ENV.INGEST_API_KEY) {
        return reply.code(401).send({ error: 'Invalid ingest key' });
      }

      //
      // 2. Validazione input
      //
      const parsed = ingestSchema.safeParse(req.body);
      if (!parsed.success) {
        return reply
          .code(400)
          .send({ error: 'Invalid body', issues: parsed.error.issues });
      }

      const data = parsed.data;

      //
      // 3. Upsert regola ModSecurity
      //    Nota: funziona solo se Rule.ruleId è marcato @unique nello schema Prisma
      //
      let ruleRecord = null;
      if (data.ruleId) {
        ruleRecord = await prisma.rule.upsert({
          where: { ruleId: data.ruleId },
          update: {
            message: data.ruleMessage ?? undefined,
            severity: data.severity ?? undefined
          },
          create: {
            ruleId: data.ruleId,
            message: data.ruleMessage ?? '',
            severity: data.severity
          }
        });
      }

      //
      // 4. Creazione evento + dettaglio richiesta associato
      //
      const event = await prisma.event.create({
        data: {
          timestamp: data.occurredAt ? new Date(data.occurredAt) : new Date(),
          sourceIp: data.sourceIp,
          destIp: data.destIp,
          uri: data.uri,
          method: data.method,
          status: data.status,
          wafAction: data.wafAction,
          ruleId: ruleRecord ? ruleRecord.id : undefined,
          requestDetail: {
            create: {
              headers: data.headers ?? '',
              body: data.body ?? null,
              userAgent: data.userAgent ?? null
            }
          }
        }
      });

      //
      // 5. Risposta
      //
      return reply.code(201).send({ id: event.id });
    }
  );
}
