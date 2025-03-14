import { http, Request, Response } from '@google-cloud/functions-framework';
import { z } from 'zod';
import {
  BodyValidationMiddleware,
  ErrorHandlerMiddleware,
  Handler,
  ResponseWrapperMiddleware,
} from '../core';

const requestSchema = z.object({
  name: z.string().min(1),
});

const helloWorldHandler = Handler.use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(requestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { name } = context.req.validatedBody as { name: string };
    context.res.json({
      message: `Hello, ${name}!`,
    });
  });

export const helloWorld = http(
  'helloWorld',
  (req: Request, res: Response): Promise<void> => {
    return helloWorldHandler.execute(req, res);
  }
);
