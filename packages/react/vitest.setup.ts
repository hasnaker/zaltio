/**
 * Vitest Setup for @zalt.io/react
 */

import { vi } from 'vitest';

// Mock window.fetch
global.fetch = vi.fn();

// Mock Response if not available
if (typeof Response === 'undefined') {
  global.Response = class Response {
    private _body: string;
    private _init: ResponseInit;
    
    constructor(body?: BodyInit | null, init?: ResponseInit) {
      this._body = body?.toString() || '';
      this._init = init || {};
    }
    
    get ok(): boolean {
      const status = this._init.status || 200;
      return status >= 200 && status < 300;
    }
    
    get status(): number {
      return this._init.status || 200;
    }
    
    get headers(): Headers {
      return new Headers(this._init.headers);
    }
    
    async json(): Promise<unknown> {
      return JSON.parse(this._body);
    }
    
    clone(): Response {
      return new Response(this._body, this._init);
    }
  } as unknown as typeof Response;
}

// Mock Headers if not available
if (typeof Headers === 'undefined') {
  global.Headers = class Headers {
    private _headers: Map<string, string>;
    
    constructor(init?: HeadersInit) {
      this._headers = new Map();
      if (init) {
        if (Array.isArray(init)) {
          init.forEach(([key, value]) => this._headers.set(key.toLowerCase(), value));
        } else if (init instanceof Headers) {
          init.forEach((value, key) => this._headers.set(key.toLowerCase(), value));
        } else {
          Object.entries(init).forEach(([key, value]) => this._headers.set(key.toLowerCase(), value));
        }
      }
    }
    
    get(name: string): string | null {
      return this._headers.get(name.toLowerCase()) || null;
    }
    
    set(name: string, value: string): void {
      this._headers.set(name.toLowerCase(), value);
    }
    
    has(name: string): boolean {
      return this._headers.has(name.toLowerCase());
    }
    
    forEach(callback: (value: string, key: string) => void): void {
      this._headers.forEach(callback);
    }
  } as unknown as typeof Headers;
}
