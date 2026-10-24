import crypto from 'node:crypto';

export class BrowserSidecarError extends Error {
  constructor(code, message = code, details = {}) {
    super(message);
    this.name = 'BrowserSidecarError';
    this.code = code;
    this.details = details;
  }
}

const now = () => Date.now();
const id = prefix => `${prefix}-${crypto.randomBytes(6).toString('hex')}`;

export class BrowserSidecar {
  constructor(engine, {route = 'BROWSER_PLAYWRIGHT'} = {}) {
    if (!engine) throw new BrowserSidecarError('ENGINE_REQUIRED');
    this.engine = engine;
    this.route = route;
    this.surfaces = new Map();
  }

  async attach(options = {}) {
    const handle = await this.engine.attach(options);
    const surfaceId = id('surface');
    this.surfaces.set(surfaceId, {handle, generation: 0, snapshot: null, attachOptions: {...options}});
    return {surface_id: surfaceId, route: this.route, capabilities: await this.engine.capabilities(handle)};
  }

  _surface(surfaceId) {
    const surface = this.surfaces.get(surfaceId);
    if (!surface) throw new BrowserSidecarError('SURFACE_NOT_FOUND', 'surface not found', {surface_id: surfaceId});
    return surface;
  }

  _materialize(surface, raw) {
    surface.generation++;
    const generation = surface.generation;
    const entities = (raw.entities || []).map((entity, index) => ({
      ref: `g${generation}e${index + 1}`,
      generation,
      role: entity.role ?? null,
      name: entity.name ?? null,
      semantic_key: entity.semantic_key ?? null,
      actions: Array.isArray(entity.actions) ? [...entity.actions] : [],
      frame_id: entity.frame_id ?? null,
      state: entity.state ?? null,
      evidence: entity.evidence ?? null,
    }));
    surface.snapshot = {
      generation,
      fingerprint: raw.fingerprint,
      entities,
      truncated: Boolean(raw.truncated),
      semantic_tree: raw.semantic_tree ?? null,
      representation: raw.representation ?? 'entities',
      semantic_chars: Number(raw.semantic_chars ?? 0),
      semantic_depth: raw.semantic_depth ?? null,
      semantic_max_chars: raw.semantic_max_chars ?? null,
      page: raw.page ?? null,
      frames: raw.frames ?? [],
    };
    return {generation, entities};
  }

  async observe(surfaceId, options = {}) {
    const surface = this._surface(surfaceId);
    const raw = await this.engine.snapshot(surface.handle, options);
    const {generation, entities} = this._materialize(surface, raw);
    const semanticTree = raw.semantic_tree ?? null;
    const payload = semanticTree && entities.length ? {semantic_tree: semanticTree, entities} : (semanticTree ?? entities);
    return {
      surface_id: surfaceId,
      generation,
      fingerprint: raw.fingerprint,
      page: raw.page ?? null,
      frames: raw.frames ?? [],
      entities,
      semantic_tree: semanticTree,
      representation: raw.representation ?? 'entities',
      semantic_chars: Number(raw.semantic_chars ?? 0),
      semantic_depth: raw.semantic_depth ?? null,
      semantic_max_chars: raw.semantic_max_chars ?? null,
      truncated: Boolean(raw.truncated),
      semantic_truncated: Boolean(raw.semantic_truncated),
      entity_truncated: Boolean(raw.entity_truncated),
      chars: JSON.stringify(payload).length,
    };
  }

  async find(surfaceId, query = {}) {
    const surface = this._surface(surfaceId);
    if (typeof this.engine.find === 'function') {
      const raw = await this.engine.find(surface.handle, query);
      const {generation, entities} = this._materialize(surface, raw);
      return {
        surface_id: surfaceId,
        generation,
        page: raw.page ?? null,
        frames: raw.frames ?? [],
        matches: entities,
        truncated: Boolean(raw.truncated),
        total_matches: Number(raw.total_matches ?? entities.length),
        snapshot_truncated: false,
        chars: JSON.stringify(entities).length,
      };
    }
    const snapshot = await this.observe(surfaceId, query.observe_options ?? {});
    const needle = String(query.text ?? '').toLowerCase();
    const role = query.role == null ? null : String(query.role).toLowerCase();
    const action = query.action == null ? null : String(query.action);
    const all = snapshot.entities.filter(entity =>
      (!needle ||
        String(entity.name ?? '').toLowerCase().includes(needle) ||
        String(entity.semantic_key ?? '').toLowerCase().includes(needle)) &&
      (!role || String(entity.role ?? '').toLowerCase() === role) &&
      (!action || entity.actions.includes(action)));
    const limit = Math.min(Math.max(Number(query.limit ?? 20), 1), 100);
    const matches = all.slice(0, limit);
    return {
      surface_id: surfaceId,
      generation: snapshot.generation,
      page: snapshot.page,
      frames: snapshot.frames,
      matches,
      truncated: all.length > limit,
      total_matches: all.length,
      snapshot_truncated: snapshot.truncated,
      chars: JSON.stringify(matches).length,
    };
  }

  _resolveRef(surface, ref, expectedGeneration) {
    if (!surface.snapshot) throw new BrowserSidecarError('SNAPSHOT_REQUIRED');
    if (expectedGeneration !== surface.snapshot.generation) {
      throw new BrowserSidecarError('STALE_TARGET', 'snapshot generation changed', {
        expected: expectedGeneration,
        actual: surface.snapshot.generation,
      });
    }
    const entity = surface.snapshot.entities.find(candidate => candidate.ref === ref);
    if (!entity) throw new BrowserSidecarError('STALE_TARGET', 'ref not present in current snapshot', {ref});
    return entity;
  }

  async _resolveEntity(surface, ref, generation) {
    const entity = this._resolveRef(surface, ref, generation);
    const resolved = await this.engine.resolve(surface.handle, entity);
    if (!resolved) throw new BrowserSidecarError('TARGET_DETACHED', 'semantic entity no longer resolves', {ref});
    if (resolved.ambiguous) throw new BrowserSidecarError('TARGET_AMBIGUOUS', 'semantic entity resolved ambiguously', {ref});
    if (resolved.changed) {
      throw new BrowserSidecarError('TARGET_MOVED', 'semantic identity changed since observation', {
        ref,
        details: resolved.details ?? null,
      });
    }
    return {entity, resolved};
  }

  async act(surfaceId, {ref, generation, action, args = {}, verify = null} = {}) {
    const started = now();
    const surface = this._surface(surfaceId);
    const before = await this.engine.fingerprint(surface.handle);
    const entity = this._resolveRef(surface, ref, generation);
    if (surface.snapshot.fingerprint !== before) {
      throw new BrowserSidecarError('STALE_TARGET', 'surface changed since observation', {
        snapshot: surface.snapshot.fingerprint,
        current: before,
      });
    }
    if (!entity.actions.includes(action)) {
      throw new BrowserSidecarError('ACTION_UNSUPPORTED', `${action} unsupported`, {
        ref,
        actions: entity.actions,
      });
    }
    const {resolved} = await this._resolveEntity(surface, ref, generation);
    let targetResolved = null;
    if (action === 'drag_to') {
      const targetRef = args?.target_ref;
      const targetGeneration = args?.target_generation ?? generation;
      if (typeof targetRef !== 'string' || !targetRef) {
        throw new BrowserSidecarError('DRAG_TARGET_REQUIRED');
      }
      const target = await this._resolveEntity(surface, targetRef, targetGeneration);
      targetResolved = target.resolved;
    }
    const result = await this.engine.act(surface.handle, resolved, action, args, {targetResolved});
    const post = await this.engine.verify(surface.handle, verify ?? result?.postcondition ?? null, {
      resolved,
      entity,
      action,
      args,
      targetResolved,
    });
    const after = await this.engine.fingerprint(surface.handle);
    const pageIdentity = typeof this.engine.identity === 'function' ? await this.engine.identity(surface.handle) : null;
    const ended = now();
    return {
      requested_operation: action,
      operation: action,
      route: this.route,
      surface_id: surfaceId,
      page_identity: pageIdentity,
      target_before: before,
      target_after: after,
      generation,
      ref,
      attempted: true,
      started_at: started,
      ended_at: ended,
      latency_ms: ended - started,
      verified: Boolean(post?.verified),
      verification_result: post ?? null,
      postcondition: post ?? null,
      physical_input_used: false,
      focus_preserved: typeof result?.focus_preserved === 'boolean' ? result.focus_preserved : null,
      cursor_preserved: typeof result?.cursor_preserved === 'boolean' ? result.cursor_preserved : null,
      fallback_chain: [],
      retries: 0,
      terminal_failure_reason: null,
      trace_refs: result?.trace_refs ?? [],
    };
  }

  async wait(surfaceId, spec, timeoutMs = 5000) {
    const surface = this._surface(surfaceId);
    const started = now();
    const result = await this.engine.waitFor(surface.handle, spec, timeoutMs);
    const ended = now();
    return {
      requested_operation: 'wait',
      operation: 'wait',
      route: this.route,
      surface_id: surfaceId,
      attempted: true,
      started_at: started,
      ended_at: ended,
      latency_ms: ended - started,
      verified: Boolean(result?.matched),
      verification_result: result ?? null,
      postcondition: result ?? null,
      physical_input_used: false,
      fallback_chain: [],
      retries: 0,
      terminal_failure_reason: null,
    };
  }

  async _navigation(surfaceId, operation, fn) {
    const surface = this._surface(surfaceId);
    await fn(surface.handle);
    surface.snapshot = null;
    const observation = await this.observe(surfaceId);
    return {operation, route: this.route, physical_input_used: false, verified: true, observation};
  }

  async navigate(surfaceId, url, timeoutMs = 10000) { return this._navigation(surfaceId, 'navigate', handle => this.engine.navigate(handle, url, timeoutMs)); }

  async back(surfaceId, timeoutMs = 10000) { return this._navigation(surfaceId, 'back', handle => this.engine.back(handle, timeoutMs)); }

  async forward(surfaceId, timeoutMs = 10000) { return this._navigation(surfaceId, 'forward', handle => this.engine.forward(handle, timeoutMs)); }

  async reload(surfaceId, timeoutMs = 10000) { return this._navigation(surfaceId, 'reload', handle => this.engine.reload(handle, timeoutMs)); }

  async identity(surfaceId) { return this.engine.identity(this._surface(surfaceId).handle); }

  async listTabs(surfaceId) {
    return this.engine.listTabs(this._surface(surfaceId).handle);
  }

  async claimTab(surfaceId, selector) {
    const surface = this._surface(surfaceId);
    const result = await this.engine.claimTab(surface.handle, selector);
    surface.snapshot = null;
    return {result, observation: await this.observe(surfaceId)};
  }

  async newTab(surfaceId, url = 'about:blank', timeoutMs = 10000) {
    const surface = this._surface(surfaceId);
    const result = await this.engine.newTab(surface.handle, url, timeoutMs);
    surface.snapshot = null;
    return {result, observation: await this.observe(surfaceId)};
  }

  async switchTab(surfaceId, pageId) {
    const surface = this._surface(surfaceId);
    const result = await this.engine.switchTab(surface.handle, pageId);
    surface.snapshot = null;
    return {result, observation: await this.observe(surfaceId)};
  }

  async closeTab(surfaceId, pageId) {
    const surface = this._surface(surfaceId);
    const result = await this.engine.closeTab(surface.handle, pageId);
    surface.snapshot = null;
    return result;
  }

  async recover(surfaceId) {
    const surface = this._surface(surfaceId);
    try {
      await this.engine.close(surface.handle);
    } catch {}
    const handle = await this.engine.attach({...surface.attachOptions});
    surface.handle = handle;
    surface.snapshot = null;
    surface.generation++;
    return {
      surface_id: surfaceId,
      route: this.route,
      recovered: true,
      generation: surface.generation,
      capabilities: await this.engine.capabilities(handle),
    };
  }

  async close(surfaceId) {
    const surface = this._surface(surfaceId);
    const cleanup = await this.engine.close(surface.handle);
    this.surfaces.delete(surfaceId);
    return {ok: true, cleanup: cleanup ?? null};
  }
}
