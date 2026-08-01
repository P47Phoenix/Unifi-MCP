/**
 * Network's structured filter DSL (FR-33, FR-34).
 *
 * Of the four APIs, only Network accepts a `filter` query parameter, and it
 * accepts a small expression grammar rather than a key/value map. Modelling it
 * as an opaque string would push every syntax mistake to a round trip and a 400
 * from the console; modelling it as validated structure means a malformed
 * timestamp or a misremembered function name is rejected here, with a message
 * that names the legal alternatives, before any HTTP request is made.
 *
 * Serialisation is the only path from structure to wire text: `serializeFilter`
 * re-parses whatever it is handed, so a hand-built object literal cannot skip
 * validation on its way into a URL.
 */
import { z } from 'zod';

/**
 * The grammar's function vocabulary, in the order the Network documentation
 * lists it. Exported because the rejection message for an unknown function has
 * to enumerate it (FR-33) and callers building UI want the same list.
 */
export const FILTER_FUNCTIONS = [
  'isNull',
  'isNotNull',
  'eq',
  'ne',
  'gt',
  'ge',
  'lt',
  'le',
  'like',
  'in',
  'notIn',
  'isEmpty',
  'contains',
  'containsAny',
  'containsAll',
  'containsExactly',
] as const;

export type FilterFunction = (typeof FILTER_FUNCTIONS)[number];

/** Take no argument at all: `state.isNull()`. */
const NULLARY_FUNCTIONS: ReadonlySet<FilterFunction> = new Set<FilterFunction>([
  'isNull',
  'isNotNull',
  'isEmpty',
]);

/** Take a SET: `id.in(1, 2, 3)`. */
const SET_FUNCTIONS: ReadonlySet<FilterFunction> = new Set<FilterFunction>([
  'in',
  'notIn',
  'containsAny',
  'containsAll',
  'containsExactly',
]);

function supportedFunctionList(): string {
  return FILTER_FUNCTIONS.join(', ');
}

function unsupportedFunctionMessage(received: unknown): string {
  const shown = typeof received === 'string' ? `"${received}"` : String(received);
  return (
    `Unsupported filter function ${shown}. Supported functions: ${supportedFunctionList()}.`
  );
}

const FilterFunctionSchema = z.enum(FILTER_FUNCTIONS, {
  errorMap: (issue, ctx) => {
    if (
      issue.code === z.ZodIssueCode.invalid_enum_value ||
      issue.code === z.ZodIssueCode.invalid_type
    ) {
      return { message: unsupportedFunctionMessage(ctx.data) };
    }
    return { message: ctx.defaultError };
  },
});

/**
 * Property names are interpolated straight into the filter string, so an
 * unconstrained name is an injection point into the grammar itself — a name
 * containing `)` or `,` would let a caller forge operators. Restrict to the
 * dotted identifiers the API actually uses.
 */
const PropertyNameSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(
    /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/,
    'Filter property must be a dotted identifier, e.g. `name` or `meta.createdAt`.',
  );

/**
 * Calendar date, optionally with a time and a zone offset. Date-only is legal
 * ISO 8601 and is what the documented `createdAt.in(2025-01-01, 2025-01-05)`
 * example uses; a space separator instead of `T` is not.
 */
const ISO_8601 =
  /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})?)?$/;

/** Regex shape alone accepts 2025-02-30; the calendar round-trip does not. */
function isIso8601(value: string): boolean {
  const m = ISO_8601.exec(value);
  if (!m) return false;

  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;

  const probe = new Date(Date.UTC(year, month - 1, day));
  if (probe.getUTCMonth() !== month - 1 || probe.getUTCDate() !== day) return false;

  if (m[4] !== undefined) {
    const hour = Number(m[4]);
    const minute = Number(m[5]);
    // 60 admitted for leap seconds, which ISO 8601 permits.
    const second = m[6] === undefined ? 0 : Number(m[6]);
    if (hour > 23 || minute > 59 || second > 60) return false;
  }
  return true;
}

const StringValueSchema = z.object({
  type: z.literal('STRING'),
  value: z.string(),
});

const IntegerValueSchema = z.object({
  type: z.literal('INTEGER'),
  value: z.number().int(),
});

const DecimalValueSchema = z.object({
  type: z.literal('DECIMAL'),
  // Infinity and NaN have no serialisation in this grammar.
  value: z.number().finite(),
});

const TimestampValueSchema = z.object({
  type: z.literal('TIMESTAMP'),
  value: z
    .string()
    .refine(isIso8601, {
      message:
        'TIMESTAMP must be ISO 8601, e.g. `2025-01-01` or `2025-01-01T09:30:00Z`.',
    }),
});

const BooleanValueSchema = z.object({
  type: z.literal('BOOLEAN'),
  value: z.boolean(),
});

const UuidValueSchema = z.object({
  type: z.literal('UUID'),
  value: z.string().uuid(),
});

const ScalarValueSchema = z.discriminatedUnion('type', [
  StringValueSchema,
  IntegerValueSchema,
  DecimalValueSchema,
  TimestampValueSchema,
  BooleanValueSchema,
  UuidValueSchema,
]);

/** SET is a container type: it is the argument shape of `in` and friends. */
const SetValueSchema = z.object({
  type: z.literal('SET'),
  values: z.array(ScalarValueSchema).min(1, 'A SET needs at least one member.'),
});

export const FilterValueSchema = z.union([ScalarValueSchema, SetValueSchema]);

export type FilterScalarValue = z.infer<typeof ScalarValueSchema>;
export type FilterSetValue = z.infer<typeof SetValueSchema>;
export type FilterValue = FilterScalarValue | FilterSetValue;

export type FilterExpression =
  | {
      kind: 'property';
      property: string;
      fn: FilterFunction;
      /** Absent for the nullary functions; a SET for the set functions. */
      value?: FilterValue;
    }
  | { kind: 'and'; operands: FilterExpression[] }
  | { kind: 'or'; operands: FilterExpression[] }
  | { kind: 'not'; operand: FilterExpression };

const PropertyExpressionObject = z.object({
  kind: z.literal('property'),
  property: PropertyNameSchema,
  fn: FilterFunctionSchema,
  value: FilterValueSchema.optional(),
});

// `and`/`or` with a single operand serialise to something the console accepts
// but that no caller means to write; requiring two keeps the intent explicit.
const AndObject = z.object({
  kind: z.literal('and'),
  operands: z.array(z.lazy(() => FilterExpressionSchema)).min(2),
});

const OrObject = z.object({
  kind: z.literal('or'),
  operands: z.array(z.lazy(() => FilterExpressionSchema)).min(2),
});

const NotObject = z.object({
  kind: z.literal('not'),
  operand: z.lazy(() => FilterExpressionSchema),
});

/**
 * Arity lives in a refinement rather than in sixteen union members: a
 * discriminated union on `kind` keeps parse errors pointed at the branch the
 * caller actually wrote, and compound operands recurse through this same
 * schema, so nested property nodes are checked at every depth.
 */
function enforceArity(expr: FilterExpression, ctx: z.RefinementCtx): void {
  if (expr.kind !== 'property') return;

  if (NULLARY_FUNCTIONS.has(expr.fn)) {
    if (expr.value !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['value'],
        message: `\`${expr.fn}\` takes no argument; remove \`value\`.`,
      });
    }
    return;
  }

  if (SET_FUNCTIONS.has(expr.fn)) {
    if (expr.value === undefined || expr.value.type !== 'SET') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['value'],
        message: `\`${expr.fn}\` takes a SET, e.g. { type: 'SET', values: [...] }.`,
      });
    }
    return;
  }

  if (expr.value === undefined || expr.value.type === 'SET') {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['value'],
      message: `\`${expr.fn}\` takes exactly one non-SET value.`,
    });
  }
}

export const FilterExpressionSchema: z.ZodType<FilterExpression, z.ZodTypeDef, unknown> = z
  .lazy(() =>
    z.discriminatedUnion('kind', [PropertyExpressionObject, AndObject, OrObject, NotObject]),
  )
  .superRefine(enforceArity);

/**
 * A literal single quote is escaped by doubling it, not by backslash: the
 * grammar has no backslash escape, so `O'Brien` must reach the wire as
 * `'O''Brien'` or the expression terminates early and the remainder is parsed
 * as operators.
 */
function serializeString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function serializeScalar(value: FilterScalarValue): string {
  switch (value.type) {
    case 'STRING':
      return serializeString(value.value);
    case 'INTEGER':
    case 'DECIMAL':
      return String(value.value);
    case 'TIMESTAMP':
      return value.value;
    case 'BOOLEAN':
      return value.value ? 'true' : 'false';
    case 'UUID':
      return value.value;
  }
}

function serializeValue(value: FilterValue): string {
  return value.type === 'SET'
    ? value.values.map(serializeScalar).join(', ')
    : serializeScalar(value);
}

function serializeNode(expr: FilterExpression): string {
  switch (expr.kind) {
    case 'property':
      return `${expr.property}.${expr.fn}(${expr.value === undefined ? '' : serializeValue(expr.value)})`;
    case 'and':
    case 'or':
      return `${expr.kind}(${expr.operands.map(serializeNode).join(', ')})`;
    case 'not':
      return `not(${serializeNode(expr.operand)})`;
  }
}

/**
 * Render an expression to the wire form Network expects.
 *
 * Parses first so that the only way to produce a filter string is through a
 * validated expression — there is no unchecked path from a caller's object
 * literal to a URL.
 */
export function serializeFilter(expr: FilterExpression): string {
  return serializeNode(FilterExpressionSchema.parse(expr));
}

/**
 * FR-34: the escape hatch. Deliberately unvalidated and passed through
 * byte-for-byte, for filters the structured input cannot yet express (a newly
 * added function, a grammar the vendored spec predates). Nothing here rewrites,
 * trims, or re-quotes the string; errors surface as the console's own 400.
 *
 * The bound is a URL-length guard, not a grammar check.
 */
export const RawFilterSchema = z
  .string()
  .min(1, 'rawFilter cannot be empty.')
  .max(8192, 'rawFilter exceeds the 8192-character URL guard.')
  .describe(
    'Raw Network filter expression, passed through verbatim and NOT validated. ' +
      'Prefer the structured `filter` input, which is checked before the request ' +
      'is sent. Syntax errors here surface as an upstream 400.',
  );

export const FILTER_CONFLICT_MESSAGE =
  'Both `filter` (structured) and `rawFilter` (verbatim escape hatch) were supplied. ' +
  'They are mutually exclusive because each produces the whole filter expression — ' +
  'there is no defined way to merge them. Supply exactly one.';

export interface FilterInput {
  filter?: FilterExpression;
  rawFilter?: string;
}

/**
 * Accepting both inputs and silently preferring one would make the ignored
 * filter invisible in the request, so the conflict is an error and names both
 * fields.
 */
export const FilterInputSchema = z
  .object({
    filter: FilterExpressionSchema.optional(),
    rawFilter: RawFilterSchema.optional(),
  })
  .superRefine((input, ctx) => {
    if (input.filter !== undefined && input.rawFilter !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['rawFilter'],
        message: FILTER_CONFLICT_MESSAGE,
      });
    }
  });

/**
 * Resolve either input form to the single query-parameter value, or null when
 * no filter was requested. Throws on the conflict rather than choosing.
 */
export function resolveFilterInput(input: FilterInput): string | null {
  if (input.filter !== undefined && input.rawFilter !== undefined) {
    throw new Error(FILTER_CONFLICT_MESSAGE);
  }
  if (input.rawFilter !== undefined) return RawFilterSchema.parse(input.rawFilter);
  if (input.filter !== undefined) return serializeFilter(input.filter);
  return null;
}
