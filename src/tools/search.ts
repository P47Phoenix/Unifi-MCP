/**
 * Ranking for `unifi_search_actions`.
 *
 * This is the entry point to 163 of the 168 operations — everything not
 * promoted to a dedicated tool is reachable only by finding it here, so
 * ranking quality is the difference between the hybrid pattern working and the
 * long tail being effectively unreachable (ADR-02).
 *
 * Two things make naive substring matching fail badly:
 *
 *  1. **Vocabulary mismatch.** Operators say "access point"; the spec says
 *     `device`. They say "wifi"; the spec says `wifi/broadcasts`. Matching
 *     literal query words against spec text ranks by coincidence.
 *  2. **Field significance.** A term in the path or operation ID identifies the
 *     resource. The same term buried in a prose description is weak evidence —
 *     `description` is where "device" appears in half the Protect spec.
 *
 * So terms are expanded through a domain vocabulary and scored per field.
 */
import type { Action, ServiceId } from '../types.js';

/** Words that carry no selection signal in a question-shaped query. */
const STOPWORDS = new Set([
  'a', 'all', 'am', 'an', 'and', 'any', 'are', 'as', 'at', 'be', 'by', 'can', 'do', 'does',
  'for', 'from', 'get', 'give', 'has', 'have', 'how', 'i', 'in', 'is', 'it', 'its', 'list',
  'me', 'my', 'of', 'on', 'or', 'our', 'show', 'that', 'the', 'their', 'them', 'there',
  'these', 'this', 'to', 'up', 'was', 'were', 'what', 'when', 'where', 'which', 'who',
  'with', 'you', 'your',
]);

/**
 * Operator vocabulary → spec vocabulary.
 *
 * Deliberately hand-written rather than derived: the mapping encodes what UniFi
 * operators actually call things, which is not recoverable from the specs.
 */
const SYNONYMS: Record<string, readonly string[]> = {
  // Infrastructure — all of it is `device` in the Network spec.
  ap: ['device'],
  aps: ['device'],
  access: ['device'],
  point: ['device'],
  points: ['device'],
  switch: ['device'],
  switches: ['device'],
  gateway: ['device'],
  gateways: ['device'],
  router: ['device'],
  udm: ['device'],
  uplink: ['device', 'port'],
  poe: ['port'],
  port: ['port'],
  ports: ['port'],
  firmware: ['device', 'firmware'],
  adopt: ['device', 'pending'],
  adopted: ['device'],
  pending: ['pending', 'device'],

  // State language.
  offline: ['device', 'state', 'status'],
  online: ['device', 'state', 'status'],
  down: ['device', 'state', 'status'],
  status: ['state', 'status'],
  health: ['state', 'status', 'statistic'],
  stats: ['statistic', 'metric'],
  statistics: ['statistic'],
  metrics: ['metric', 'statistic'],
  usage: ['statistic', 'metric'],

  // Endpoints on the network, as opposed to infrastructure.
  client: ['client'],
  clients: ['client'],
  laptop: ['client'],
  laptops: ['client'],
  phone: ['client'],
  phones: ['client'],
  connected: ['client'],
  guest: ['guest', 'hotspot', 'voucher'],
  guests: ['guest', 'hotspot', 'voucher'],
  voucher: ['voucher', 'hotspot'],
  vouchers: ['voucher', 'hotspot'],
  block: ['client', 'action'],
  unblock: ['client', 'action'],

  // Wireless.
  wifi: ['wifi', 'wlan', 'broadcast'],
  wireless: ['wifi', 'wlan', 'broadcast'],
  ssid: ['wifi', 'wlan', 'broadcast'],
  wlan: ['wifi', 'wlan', 'broadcast'],
  psk: ['wifi', 'wlan'],

  // Protect.
  camera: ['camera'],
  cameras: ['camera'],
  nvr: ['nvr', 'camera'],
  recording: ['recording'],
  snapshot: ['snapshot'],
  motion: ['event'],
  doorbell: ['camera', 'chime'],
  sensor: ['sensor'],
  sensors: ['sensor'],
  light: ['light'],
  lights: ['light'],
  siren: ['siren'],
  alarm: ['alarm', 'siren'],
  viewer: ['viewer', 'liveview'],
  liveview: ['liveview', 'viewer'],

  // Topology and cloud.
  site: ['site'],
  sites: ['site'],
  network: ['network'],
  networks: ['network'],
  vlan: ['network'],
  subnet: ['network'],
  console: ['host', 'console'],
  consoles: ['host', 'console'],
  host: ['host'],
  hosts: ['host'],
  isp: ['isp'],
  wan: ['isp', 'sd-wan'],
  sdwan: ['sd-wan'],
  firewall: ['firewall'],
  rule: ['rule', 'policy'],
  rules: ['rule', 'policy'],
  policy: ['policy'],
  policies: ['policy'],
  acl: ['acl'],
  dns: ['dns'],
  zone: ['zone'],
  zones: ['zone'],

  // Mobility.
  mobility: ['mobility'],
  sim: ['mobility', 'sim'],
  cellular: ['mobility'],
  lte: ['mobility'],
  workspace: ['workspace'],
};

/**
 * Per-field weights.
 *
 * `resource` — the terminal non-parameter path segment — is by far the
 * strongest signal: it is what the endpoint is *about*. Matching elsewhere in
 * the path is much weaker, because almost every Network path is prefixed
 * `/v1/sites/{siteId}/…`, so a bare path match on "site" hits nearly the entire
 * API and ranks by coincidence.
 */
const WEIGHT = {
  resourceExact: 10,
  resourcePartial: 6,
  id: 4,
  summary: 3,
  pathOther: 2,
  tag: 2,
  description: 1,
} as const;

/** Strip a trailing plural so `device` and `devices` compare equal. */
function singular(word: string): string {
  if (word.endsWith('ies') && word.length > 4) return `${word.slice(0, -3)}y`;
  if (word.endsWith('es') && /(?:ch|sh|ss|x|z)es$/.test(word)) return word.slice(0, -2);
  if (word.endsWith('s') && !word.endsWith('ss') && word.length > 3) return word.slice(0, -1);
  return word;
}

/** The resource an endpoint addresses: its last non-parameter path segment. */
export function resourceOf(path: string): string {
  const segments = path.split('/').filter((s) => s && !s.startsWith('{') && !s.startsWith('*'));
  const last = segments[segments.length - 1];
  if (!last) return '';
  return /^v\d+$/i.test(last) ? '' : last.toLowerCase();
}

export interface ScoredAction {
  action: Action;
  score: number;
}

export interface SearchOptions {
  service?: ServiceId;
  actionClass?: 'read' | 'write';
  limit?: number;
}

/**
 * One concept from the query, with the spec vocabulary it can match.
 *
 * Grouping matters for scoring: an action must not look like a better match
 * merely because one query word happens to carry three synonyms. "wifi"
 * expanding to wifi/wlan/broadcast would otherwise triple its contribution and
 * bury the client endpoint for "who is connected to my wifi".
 */
export interface QueryConcept {
  original: string;
  variants: string[];
}

export function expandConcepts(query: string): QueryConcept[] {
  const rawTerms = query
    .toLowerCase()
    .split(/[^a-z0-9-]+/)
    .filter((t) => t.length > 1 && !STOPWORDS.has(t));

  const concepts: QueryConcept[] = [];
  const seen = new Set<string>();

  for (const term of rawTerms) {
    if (seen.has(term)) continue;
    seen.add(term);
    const synonyms = SYNONYMS[term];
    if (synonyms) {
      // The mapping REPLACES the literal rather than joining it. "access" in
      // operator speech means an access point, i.e. a device — keeping the
      // English word as well makes it match "Access Control List" in the ACL
      // descriptions, which is how "which access points are offline" used to
      // return firewall rules.
      concepts.push({ original: term, variants: [...synonyms] });
      continue;
    }
    const variants = [term];
    // Cheap depluralisation catches spec nouns the synonym table does not list.
    if (term.endsWith('s') && term.length > 3) variants.push(term.slice(0, -1));
    concepts.push({ original: term, variants });
  }
  return concepts;
}

/** Flattened variants, kept for callers that only want the term list. */
export function expandQuery(query: string): string[] {
  return [...new Set(expandConcepts(query).flatMap((c) => c.variants))];
}

/**
 * True for endpoints that return a collection.
 *
 * "Which access points are offline" wants the collection, not the by-id
 * lookup; without this the item endpoint often outranks the list because a
 * path with `{deviceId}` matches `device` twice.
 */
function isCollectionEndpoint(action: Action): boolean {
  return action.method === 'GET' && !/\{[^}]+\}\/?$/.test(action.path);
}

export function scoreAction(action: Action, concepts: readonly QueryConcept[]): number {
  if (concepts.length === 0) return 0;

  const path = action.path.toLowerCase();
  const id = action.id.toLowerCase();
  const summary = action.summary.toLowerCase();
  const description = action.description.toLowerCase();
  const tags = action.tags.join(' ').toLowerCase();
  const resource = resourceOf(action.path);
  const resourceSingular = singular(resource);

  let score = 0;
  let matched = 0;

  for (const concept of concepts) {
    // One concept contributes once, at the strength of its best variant.
    let best = 0;
    for (const variant of concept.variants) {
      const term = singular(variant);
      let hit = 0;
      if (resource && (resourceSingular === term || resource === variant)) {
        hit = WEIGHT.resourceExact;
      } else if (resource && (resource.includes(term) || term.includes(resourceSingular))) {
        hit = WEIGHT.resourcePartial;
      }
      if (id.includes(term)) hit = Math.max(hit, WEIGHT.id);
      if (summary.includes(term)) hit = Math.max(hit, WEIGHT.summary);
      if (tags.includes(term)) hit = Math.max(hit, WEIGHT.tag);
      if (path.includes(term)) hit = Math.max(hit, WEIGHT.pathOther);
      if (description.includes(term)) hit = Math.max(hit, WEIGHT.description);
      best = Math.max(best, hit);
    }
    if (best > 0) matched += 1;
    score += best;
  }

  if (matched === 0) return 0;

  // An action matching several distinct query concepts is far more likely to be
  // the intended one than one matching a single concept strongly.
  score *= 1 + (matched - 1) * 0.5;

  if (isCollectionEndpoint(action)) score += 3;

  // Writes are a minority of intents and the costlier thing to surface by
  // mistake, so they need to earn their place rather than tie with a read.
  if (action.actionClass === 'write') score -= 2;

  // Deterministic shape tiebreak, small enough never to overturn a real signal.
  // Between two endpoints about the same resource, the simpler and more general
  // one is the likelier intent: `/v1/hosts` over `/v1/connector/consoles/{id}/*path`.
  const requiredParams = action.parameters.filter((p) => p.location === 'path').length;
  const segments = action.path.split('/').filter(Boolean).length;
  score -= requiredParams * 0.5 + segments * 0.1;

  return score;
}

export function searchActions(
  actions: readonly Action[],
  query: string,
  options: SearchOptions = {},
): ScoredAction[] {
  const concepts = expandConcepts(query);
  const limit = Math.min(Math.max(options.limit ?? 10, 1), 25);

  return actions
    .filter(
      (a) =>
        (!options.service || a.service === options.service) &&
        (!options.actionClass || a.actionClass === options.actionClass),
    )
    .map((action) => ({ action, score: scoreAction(action, concepts) }))
    .filter((s) => s.score > 0)
    // Ties break on ID so results are stable across calls (NFR-22).
    .sort((a, b) => b.score - a.score || a.action.id.localeCompare(b.action.id))
    .slice(0, limit);
}
