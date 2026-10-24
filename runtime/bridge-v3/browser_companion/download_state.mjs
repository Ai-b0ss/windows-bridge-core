const TERMINAL = new Set(['COMPLETE', 'TIMEOUT', 'AMBIGUOUS', 'INTERRUPTED', 'FAILED', 'CLEANED']);
const ACTIVE = new Set(['PREPARED', 'MATCHED', 'IN_PROGRESS']);
const basename = value => String(value || '').replaceAll('\\', '/').split('/').pop() || '';
const safeName = value => {
  const raw = basename(value).replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').trim();
  return raw && raw !== '.' && raw !== '..' ? raw.slice(0, 180) : 'download.bin';
};
const clone = value => JSON.parse(JSON.stringify(value));

export class DownloadOperationStore {
  constructor({clock = () => Date.now(), maxOperations = 32} = {}) {
    this.clock = clock;
    this.maxOperations = maxOperations;
    this.operations = new Map();
    this.byDownloadId = new Map();
  }

  _refresh(op) {
    if (ACTIVE.has(op.state) && this.clock() > op.expires_at) op.state = 'TIMEOUT';
    return op;
  }

  prepare(spec = {}) {
    const operationId = String(spec.operation_id || '');
    const expectedUrl = String(spec.expected_url || '');
    if (!/^[A-Za-z0-9._-]{8,96}$/.test(operationId)) throw new Error('OPERATION_ID_INVALID');
    if (!/^https?:\/\//.test(expectedUrl)) throw new Error('EXPECTED_URL_REQUIRED');
    if (this.operations.has(operationId)) throw new Error('OPERATION_EXISTS');
    if (this.operations.size >= this.maxOperations) throw new Error('OPERATION_LIMIT');
    const timeoutMs = Math.min(Math.max(Number(spec.timeout_ms || 10000), 250), 30000);
    const now = this.clock();
    const op = {
      operation_id: operationId,
      state: 'PREPARED',
      expected_url: expectedUrl,
      expected_filename: spec.expected_filename ? safeName(spec.expected_filename) : null,
      expected_mime: spec.expected_mime ? String(spec.expected_mime) : null,
      expected_size: Number.isFinite(Number(spec.expected_size)) ? Number(spec.expected_size) : null,
      created_at: now,
      expires_at: now + timeoutMs,
      candidates: [],
      matched_id: null,
      item: null,
      terminal_reason: null,
      cleanup_complete: false,
    };
    this.operations.set(operationId, op);
    return this.publicStatus(op);
  }

  _matches(op, item) {
    this._refresh(op);
    if (!ACTIVE.has(op.state)) return false;
    const urls = [item?.url, item?.finalUrl].filter(Boolean).map(String);
    if (!urls.includes(op.expected_url)) return false;
    if (op.expected_filename && basename(item?.filename) !== op.expected_filename) return false;
    if (op.expected_mime && item?.mime && String(item.mime) !== op.expected_mime) return false;
    if (op.expected_size !== null && Number(item?.totalBytes) > 0 && Number(item.totalBytes) !== op.expected_size) return false;
    return true;
  }

  onCreated(item) {
    const id = Number(item?.id);
    if (!Number.isInteger(id)) return null;
    const matches = [...this.operations.values()].filter(op => this._matches(op, item));
    if (matches.length === 0) return null;
    if (matches.length > 1) {
      for (const op of matches) {
        if (!op.candidates.includes(id)) op.candidates.push(id);
        op.state = 'AMBIGUOUS';
        op.matched_id = null;
        op.terminal_reason = 'DOWNLOAD_AMBIGUOUS';
      }
      return {ambiguous: true, operation_ids: matches.map(op => op.operation_id)};
    }
    const op = matches[0];
    if (op.candidates.includes(id)) return {operation_id: op.operation_id, duplicate: true};
    op.candidates.push(id);
    if (op.candidates.length > 1) {
      op.state = 'AMBIGUOUS';
      op.matched_id = null;
      op.terminal_reason = 'DOWNLOAD_AMBIGUOUS';
      return {operation_id: op.operation_id, ambiguous: true};
    }
    op.state = 'MATCHED';
    op.matched_id = id;
    op.item = clone(item);
    this.byDownloadId.set(id, op.operation_id);
    return {operation_id: op.operation_id, matched: true};
  }

  filenameSuggestion(item) {
    const id = Number(item?.id);
    const operationId = this.byDownloadId.get(id);
    if (!operationId) return null;
    const op = this._refresh(this.operations.get(operationId));
    if (!op || op.state !== 'MATCHED' || op.matched_id !== id) return null;
    const filename = op.expected_filename || safeName(item?.filename);
    return {operation_id: operationId, filename: `FF-CUA/${operationId}/${filename}`};
  }

  onChanged(item) {
    const id = Number(item?.id);
    const operationId = this.byDownloadId.get(id);
    if (!operationId) return null;
    const op = this._refresh(this.operations.get(operationId));
    if (!op || op.state === 'AMBIGUOUS' || op.state === 'CLEANED') return this.publicStatus(op);
    op.item = clone(item);
    const state = String(item?.state || '');
    if (state === 'complete') {
      op.state = 'COMPLETE';
      op.terminal_reason = null;
    } else if (state === 'interrupted') {
      op.state = 'INTERRUPTED';
      op.terminal_reason = String(item?.error || 'DOWNLOAD_INTERRUPTED');
    } else if (op.state === 'MATCHED') {
      op.state = 'IN_PROGRESS';
    }
    return this.publicStatus(op);
  }

  publicStatus(opOrId) {
    const op = typeof opOrId === 'string' ? this.operations.get(opOrId) : opOrId;
    if (!op) throw new Error('OPERATION_UNKNOWN');
    this._refresh(op);
    return {
      operation_id: op.operation_id,
      state: op.state,
      matched: op.candidates.length === 1 && op.matched_id !== null && op.state !== 'AMBIGUOUS',
      completed: op.state === 'COMPLETE',
      candidate_count: op.candidates.length,
      matched_id: op.matched_id,
      item: op.item ? clone(op.item) : null,
      terminal_reason: op.terminal_reason,
      cleanup_complete: op.cleanup_complete,
      terminal: TERMINAL.has(op.state),
    };
  }

  status(operationId) {
    return this.publicStatus(String(operationId || ''));
  }

  cleanupTargets(operationId) {
    const op = this.operations.get(String(operationId || ''));
    if (!op) throw new Error('OPERATION_UNKNOWN');
    this._refresh(op);
    if (op.state === 'CLEANED') throw new Error('STALE_OPERATION');
    if (op.candidates.length === 0) return {operation_id: op.operation_id, ids: [], state: op.state};
    if (op.candidates.length !== 1 || op.matched_id !== op.candidates[0] || op.state === 'AMBIGUOUS')
      throw new Error('CLEANUP_OWNERSHIP_UNPROVEN');
    return {operation_id: op.operation_id, ids: [op.matched_id], state: op.state};
  }

  markCleaned(operationId) {
    const op = this.operations.get(String(operationId || ''));
    if (!op) throw new Error('OPERATION_UNKNOWN');
    if (op.state === 'CLEANED') throw new Error('STALE_OPERATION');
    for (const id of op.candidates) this.byDownloadId.delete(id);
    op.state = 'CLEANED';
    op.cleanup_complete = true;
    op.matched_id = null;
    op.item = null;
    return this.publicStatus(op);
  }
}

export const downloadStateInternals = {basename, safeName};
