import { useState } from 'react';

import { JsonView } from './JsonView';
import { KeyValueTable } from './KeyValueTable';
import type { ActionResult, ExecutedRequest } from '../lib/actions';

type Props = {
  title: string;
  result: ActionResult<unknown> | null;
  loading: boolean;
};

export function ResponsePanel({ title, result, loading }: Props) {
  const errorAsObject = isPlainObject(result?.error) ? (result!.error as Record<string, unknown>) : null;
  const errorAsString = typeof result?.error === 'string' ? result.error : null;
  const hasStructuredBody = result?.data !== undefined && result.data !== null && typeof result.data === 'object';
  const showExecuted = result?.executedRequest !== undefined;

  return (
    <section className="response-panel">
      <header>
        <h2>{title}</h2>
        {loading && <span className="badge loading">running...</span>}
        {result && !loading && (
          <span className={`badge ${result.ok ? 'ok' : 'fail'}`}>{result.ok ? 'success' : 'failed'}</span>
        )}
      </header>

      {result && (
        <>
          {result.httpStatus !== undefined && (
            <p className="muted">HTTP {result.httpStatus}</p>
          )}
          {errorAsString && !errorAsObject && !hasStructuredBody && (
            <div className="alert error">
              <strong>Error:</strong> {errorAsString}
            </div>
          )}
          {errorAsObject && (
            <div className="alert error">
              <strong>Error:</strong>
              <JsonView data={errorAsObject} initialDepth={1} />
            </div>
          )}
          {hasStructuredBody && (
            <JsonView data={result.data} initialDepth={2} />
          )}

          {/* === EXECUTED REQUEST — exactly what was sent on the wire === */}
          {showExecuted && result.executedRequest && (
            <ExecutedRequestView req={result.executedRequest} />
          )}

          {result.log.length > 0 && (
            <details open>
              <summary>Trace ({result.log.length} step{result.log.length === 1 ? '' : 's'})</summary>
              <ol className="trace">
                {result.log.map((line, i) => (
                  <li key={i}>{line}</li>
                ))}
              </ol>
            </details>
          )}
        </>
      )}

      {!result && !loading && (
        <p className="muted">Submit the form to see the response and trace here.</p>
      )}
    </section>
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// =============================================================================
// ExecutedRequestView: renders the ACTUAL HTTP request that was sent
// (with real DPoP JWT, real JWE compact, real headers, real body).
// =============================================================================
function ExecutedRequestView({ req }: { req: ExecutedRequest }) {
  const [copied, setCopied] = useState<string | null>(null);
  const curl = buildCurl(req);

  const copy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      setCopied(null);
    }
  };

  return (
    <div className="executed-request">
      <h3 className="executed-request-title">
        REQUEST SENT — exactamente lo que salió en la red
      </h3>
      <p className="muted small">
        Este es el HTTP request que se acaba de enviar a aegis-core, con todos los valores
        reales (no placeholders). Útil para verificar 100% que el browser está hablando
        el protocolo correcto.
      </p>

      <KeyValueTable
        title="HTTP line"
        rows={[
          { label: 'Method', value: <code>{req.method}</code> },
          { label: 'URL', value: <code>{req.url}</code>, mono: true },
        ]}
      />

      <KeyValueTable
        title="Headers (finales, los que se enviaron)"
        rows={Object.entries(req.headers).map(([k, v]) => ({
          label: k,
          value: <code className="header-value">{v}</code>,
          mono: true,
        }))}
      />

      {req.dpopProofJwt && (
        <section className="executed-section">
          <h4 className="executed-section-title">DPoP proof (raw compact JWT firmado)</h4>
          <div className="executed-toolbar">
            <button type="button" className="executed-copy" onClick={() => copy('dpop', req.dpopProofJwt!)}>
              {copied === 'dpop' ? 'Copied!' : 'Copy JWT'}
            </button>
            <span className="muted small">length: {req.dpopProofJwt.length} chars</span>
          </div>
          <pre className="code-block compact executed-dpop-jwt">{req.dpopProofJwt}</pre>
          {req.dpopHeader && req.dpopPayload && (
            <div className="executed-dpop-decoded">
              <details>
                <summary>Decoded DPoP proof (header + payload)</summary>
                <div className="executed-grid">
                  <div>
                    <p className="preview-label">header (base64url-decoded)</p>
                    <JsonView data={req.dpopHeader} initialDepth={4} />
                  </div>
                  <div>
                    <p className="preview-label">payload (base64url-decoded)</p>
                    <JsonView data={req.dpopPayload} initialDepth={3} />
                  </div>
                </div>
              </details>
            </div>
          )}
        </section>
      )}

      {req.jweCompact && (
        <section className="executed-section">
          <h4 className="executed-section-title">JWE compact (lo que viaja encriptado en el body)</h4>
          <div className="executed-toolbar">
            <button type="button" className="executed-copy" onClick={() => copy('jwe', req.jweCompact!)}>
              {copied === 'jwe' ? 'Copied!' : 'Copy JWE'}
            </button>
            <span className="muted small">length: {req.jweCompact.length} chars (5 segments joined by .)</span>
          </div>
          <pre className="code-block compact executed-jwe-jwt">{req.jweCompact}</pre>
          {req.jwePlaintext && (
            <details className="executed-jwe-plaintext">
              <summary>Decrypted plaintext (lo que aegis-core verá después de descifrar)</summary>
              <JsonView data={req.jwePlaintext} initialDepth={4} />
            </details>
          )}
        </section>
      )}

      {(req.rawBody || req.rawBodyBytes) && (
        <section className="executed-section">
          <h4 className="executed-section-title">Request body</h4>
          {req.rawBody && <JsonView data={req.rawBody} initialDepth={4} />}
          {req.rawBodyBytes && (
            <details>
              <summary>Raw bytes (string enviado tal cual al servidor)</summary>
              <pre className="code-block compact">{req.rawBodyBytes}</pre>
            </details>
          )}
        </section>
      )}

      <section className="executed-section">
        <h4 className="executed-section-title">curl equivalente (copy-pasteable)</h4>
        <div className="executed-toolbar">
          <button type="button" className="executed-copy" onClick={() => copy('curl', curl)}>
            {copied === 'curl' ? 'Copied!' : 'Copy curl'}
          </button>
          <span className="muted small">para reproducir la request con curl/Postman/etc.</span>
        </div>
        <pre className="code-block compact executed-curl">{curl}</pre>
      </section>
    </div>
  );
}

/** Build a copy-pasteable curl command from an ExecutedRequest. */
function buildCurl(req: ExecutedRequest): string {
  const lines: string[] = [];
  let url = req.url;
  // Strip the Vite-proxy prefix for the curl — curl talks to aegis-core directly.
  if (url.includes('/api/v1/internal/')) {
    url = url.replace(/\/internal\//, '/api/v1/internal/');
  } else if (url.startsWith('/api/v1/')) {
    // already aegis-core path
  }
  lines.push(`curl -X ${req.method} '${url}' \\`);
  for (const [k, v] of Object.entries(req.headers)) {
    lines.push(`  -H '${k}: ${escapeSingle(v)}' \\`);
  }
  if (req.jweCompact) {
    // JWE body — show the outer envelope shape
    const body = {
      user_identifier: req.jwePlaintext?.user_identifier,
      device_context: req.jwePlaintext?.device_context,
      secure_payload: req.jweCompact,
    };
    lines.push(`  -d '${escapeSingle(JSON.stringify(body, null, 2))}' \\`);
  } else if (req.rawBodyBytes) {
    lines.push(`  -d '${escapeSingle(req.rawBodyBytes)}' \\`);
  } else if (req.rawBody) {
    lines.push(`  -d '${escapeSingle(JSON.stringify(req.rawBody, null, 2))}' \\`);
  }
  // remove trailing backslash on the last line
  if (lines[lines.length - 1].endsWith(' \\')) {
    lines[lines.length - 1] = lines[lines.length - 1].slice(0, -2);
  }
  return lines.join('\n');
}

function escapeSingle(s: string): string {
  return s.replace(/'/g, "'\\''");
}
