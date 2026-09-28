import axios from 'axios';
import { PcapAnalysisResponse, ProtocolAuditResult, ScanResponse } from './types';

function getInitialBaseUrl(): string {
  if (typeof window !== 'undefined') {
    try {
      const saved = localStorage.getItem('aegis_console_settings');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed?.apiBaseUrl) return parsed.apiBaseUrl;
      }
    } catch {
      // fallback
    }
  }
  // Same-origin by default. The Vite dev server proxies /api and /health to the
  // local backend, and a production deployment reverse-proxies the same paths, so
  // the built bundle never embeds a hardcoded backend host.
  return import.meta.env.VITE_API_BASE_URL || '';
}

export const apiClient = axios.create({
  baseURL: getInitialBaseUrl(),
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

apiClient.interceptors.request.use((config) => {
  const apiKey = typeof window === 'undefined' ? null : sessionStorage.getItem('aegis_api_key');
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey;
  } else {
    delete config.headers['X-API-Key'];
  }
  return config;
});

export function setApiBaseUrl(newBaseUrl: string) {
  // An empty value means "same origin as this page" (dev proxy / reverse proxy).
  const normalized = (newBaseUrl ?? '').trim().replace(/\/+$/, '');
  if (apiClient.defaults.baseURL !== normalized) {
    apiClient.defaults.baseURL = normalized;
  }
}

export function setApiKey(apiKey: string) {
  if (typeof window === 'undefined') return;
  if (apiKey) {
    sessionStorage.setItem('aegis_api_key', apiKey);
  } else {
    sessionStorage.removeItem('aegis_api_key');
  }
}

/** Returns the operator-supplied API key for this browser session, if any. */
export function getApiKey(): string {
  if (typeof window === 'undefined') return '';
  return sessionStorage.getItem('aegis_api_key') ?? '';
}

/** True when a key is present for this session; no /api/* call can succeed without one. */
export function hasApiKey(): boolean {
  return getApiKey().trim().length > 0;
}
export interface BackendHealthResult {
  online: boolean;
  endpoint: string;
  statusCode: number | null;
  detail: string;
}

function resolveHealthEndpoint(): string {
  const baseUrl = (apiClient.defaults.baseURL || '').replace(/\/+$/, '');
  return `${baseUrl}/health`;
}

/**
 * Performs a live GET /health against the configured apiBaseUrl and reports the
 * actual endpoint, HTTP status code, and failure reason so the UI can display
 * real health telemetry instead of cached booleans or hardcoded ports.
 */
export async function getBackendHealth(): Promise<BackendHealthResult> {
  const endpoint = resolveHealthEndpoint();
  try {
    const res = await apiClient.get('/health', { timeout: 3000 });
    return {
      online: res.status >= 200 && res.status < 300,
      endpoint,
      statusCode: res.status,
      detail: `HTTP ${res.status}`
    };
  } catch (err) {
    if (axios.isAxiosError(err)) {
      const statusCode = err.response?.status ?? null;
      const detail = statusCode
        ? `HTTP ${statusCode}`
        : err.code === 'ECONNABORTED'
          ? 'request timed out'
          : err.message || 'unreachable';
      return { online: false, endpoint, statusCode, detail };
    }
    return {
      online: false,
      endpoint,
      statusCode: null,
      detail: err instanceof Error ? err.message : 'unreachable'
    };
  }
}

export async function checkBackendHealth(): Promise<boolean> {
  const result = await getBackendHealth();
  return result.online;
}

export async function scanDomain(domain: string, isCustomerFacing = true): Promise<{ data: ScanResponse; isFallback: boolean }> {
  const res = await apiClient.post<ScanResponse>('/api/scan', { domain, is_customer_facing: isCustomerFacing }, { timeout: 30000 });
  return { data: res.data, isFallback: false };
}

export async function scanPcap(file: File): Promise<{ data: PcapAnalysisResponse; isFallback: boolean; error?: string }> {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiClient.post<PcapAnalysisResponse>('/api/analyze-pcap', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      },
      timeout: 20000
    });
    return { data: res.data, isFallback: false };
  } catch (err: any) {
    const message = err.response?.data?.detail || err.message || 'PCAP analysis failed';
    console.error(`[AegisCrypta API] PCAP scan request failed: ${message}`);
    // Never substitute mock data - security tools must show real failures
    throw new Error(`PCAP analysis failed: ${message}`);
  }
}

export async function probeHost(host: string, port = 25, protocol = 'smtp', useStarttls = true): Promise<{ data: ProtocolAuditResult | null; isFallback: boolean }> {
  try {
    const res = await apiClient.post<ProtocolAuditResult>('/api/crypto/probe', {
      host,
      port,
      protocol,
      use_starttls: useStarttls
    });
    return { data: res.data, isFallback: false };
  } catch {
    return { data: null, isFallback: true };
  }
}

export async function fetchPdfReport(domain: string): Promise<Blob | null> {
  try {
    const res = await apiClient.post('/api/export-pdf', { domain }, {
      responseType: 'blob',
      timeout: 15000
    });
    return new Blob([res.data], { type: 'application/pdf' });
  } catch (err) {
    console.warn('[AegisCrypta API] PDF endpoint failed or unavailable:', err);
    return null;
  }
}

export async function fetchHtmlReport(domain: string): Promise<string | null> {
  try {
    const res = await apiClient.post<string>('/api/export-html', { domain }, {
      responseType: 'text',
      timeout: 15000
    });
    return res.data;
  } catch (err) {
    console.warn('[AegisCrypta API] HTML export endpoint failed:', err);
    return null;
  }
}
