export class ApiError extends Error {
  status: number;
  payload: unknown;

  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.payload = payload;
  }
}

async function readPayload(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }

  const text = await response.text();
  return text || null;
}

function extractMessage(payload: unknown, fallback: string): string {
  if (payload && typeof payload === 'object') {
    const record = payload as Record<string, unknown>;
    if (typeof record.error === 'string' && record.error.trim()) {
      return record.error;
    }
    if (typeof record.message === 'string' && record.message.trim()) {
      return record.message;
    }
  }
  if (typeof payload === 'string' && payload.trim()) {
    return payload;
  }
  return fallback;
}

export async function apiFetch<T>(input: RequestInfo | URL, init: RequestInit = {}): Promise<T> {
  try {
    const response = await fetch(input, {
      credentials: 'same-origin',
      ...init,
    });
    const payload = await readPayload(response);

    if (!response.ok) {
      window.dispatchEvent(new CustomEvent('app:event', { detail: { type: 'error' } }));
      throw new ApiError(
        extractMessage(payload, `Request failed with status ${response.status}`),
        response.status,
        payload,
      );
    }

    if (init.method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(init.method.toUpperCase())) {
      window.dispatchEvent(new CustomEvent('app:event', { detail: { type: 'success' } }));
    }

    return payload as T;
  } catch (error) {
    if (!(error instanceof ApiError)) {
      window.dispatchEvent(new CustomEvent('app:event', { detail: { type: 'error' } }));
    }
    throw error;
  }
}

export async function apiJSON<T>(
  input: RequestInfo | URL,
  body: unknown,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers || {});
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  return apiFetch<T>(input, {
    ...init,
    headers,
    body: JSON.stringify(body),
  });
}

export function messageFromError(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'Unexpected request error';
}
