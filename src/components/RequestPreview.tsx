import { KeyValueTable } from './KeyValueTable';
import { JsonView } from './JsonView';

export type RequestPreviewProps = {
  /** Section title shown at the top of the expanded panel (e.g. "Request", "What aegis-core validates"). */
  title?: string;
  method: string;
  url: string;
  headers: Array<{ name: string; value: string }>;
  dpopProof?: {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    wireFormat: string;
  };
  jweBody?: {
    encrypted: string;
    plaintextShape: Record<string, unknown>;
  };
  rawBody?: Record<string, unknown>;
  rawBodyBytes?: string;
  aegisValidates: string[];
  expectedHttp: string;
  expectedBody: string;
  /** Optional: "Why" section explaining the rationale of each piece. */
  why?: Array<{ q: string; a: string }>;
  /** Optional: which task-spec cases this request exercises. */
  casesCovered?: string[];
  /** Default open. The parent still controls collapsed state via the `defaultExpanded` prop. */
  defaultExpanded?: boolean;
  /** Optional extra sections (e.g. backend trace). */
  extra?: React.ReactNode;
};

/**
 * Reusable, fully-detailed request-preview panel. Used by:
 *  - SecurityTestView (one per scenario card)
 *  - CreateUserView, LoginView, LogoutView, IntrospectView (one per tab)
 *
 * The panel is wrapped in a native <details> element so the parent doesn't
 * need to manage open/close state — but it can be controlled via `defaultExpanded`.
 */
export function RequestPreview({
  title = 'Request preview',
  method,
  url,
  headers,
  dpopProof,
  jweBody,
  rawBody,
  rawBodyBytes,
  aegisValidates,
  expectedHttp,
  expectedBody,
  why,
  casesCovered,
  defaultExpanded = false,
  extra,
}: RequestPreviewProps) {
  return (
    <details className="request-preview" {...(defaultExpanded ? { open: true } : {})}>
      <summary className="request-preview-toggle">
        <span className="request-preview-caret" aria-hidden="true">+</span>
        <span className="request-preview-label">{title}</span>
        <span className="request-preview-hint">click para ver headers, body, DPoP, JWE y validaciones</span>
      </summary>

      <div className="request-preview-body">
        <div className="preview-section">
          <h5 className="preview-section-title">Request</h5>
          <KeyValueTable
            rows={[
              { label: 'Method', value: <code>{method}</code> },
              { label: 'URL', value: <code className="header-value">{url}</code>, mono: true },
            ]}
          />
        </div>

        <div className="preview-section">
          <h5 className="preview-section-title">Headers</h5>
          <KeyValueTable
            rows={headers.map((h) => ({
              label: h.name,
              value: <code className="header-value">{h.value}</code>,
              mono: true,
            }))}
          />
        </div>

        {dpopProof && (
          <div className="preview-section">
            <h5 className="preview-section-title">DPoP proof</h5>
            <div className="preview-grid">
              <div>
                <p className="preview-label">Header</p>
                <JsonView data={dpopProof.header} initialDepth={4} />
              </div>
              <div>
                <p className="preview-label">Payload</p>
                <JsonView data={dpopProof.payload} initialDepth={3} />
              </div>
              <div className="preview-full">
                <p className="preview-label">Wire format (compact JWT)</p>
                <pre className="code-block compact">{dpopProof.wireFormat}</pre>
              </div>
            </div>
          </div>
        )}

        {jweBody && (
          <div className="preview-section">
            <h5 className="preview-section-title">Request body (JWE envelope)</h5>
            <div className="preview-grid">
              <div>
                <p className="preview-label">Plaintext que aegis-core descifrará</p>
                <JsonView data={jweBody.plaintextShape} initialDepth={4} />
              </div>
              <div className="preview-full">
                <p className="preview-label">Encrypted (lo que viaja en la red)</p>
                <pre className="code-block compact">{jweBody.encrypted}</pre>
              </div>
            </div>
          </div>
        )}

        {rawBody && (
          <div className="preview-section">
            <h5 className="preview-section-title">Request body (JSON)</h5>
            <JsonView data={rawBody} initialDepth={4} />
            {rawBodyBytes && (
              <pre className="code-block compact">{rawBodyBytes}</pre>
            )}
          </div>
        )}

        {why && why.length > 0 && (
          <div className="preview-section">
            <h5 className="preview-section-title">¿Por qué?</h5>
            <dl className="why-list">
              {why.map((item, i) => (
                <div key={i} className="why-item">
                  <dt>{item.q}</dt>
                  <dd>{item.a}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}

        <div className="preview-section">
          <h5 className="preview-section-title">What aegis-core validates</h5>
          <ul className="validation-list">
            {aegisValidates.map((v, i) => (
              <li key={i}>{v}</li>
            ))}
          </ul>
        </div>

        <div className="preview-section">
          <h5 className="preview-section-title">Expected response</h5>
          <KeyValueTable
            rows={[
              { label: 'HTTP', value: <code>{expectedHttp}</code> },
              { label: 'Body', value: <code>{expectedBody}</code> },
            ]}
          />
        </div>

        {casesCovered && casesCovered.length > 0 && (
          <div className="preview-section">
            <h5 className="preview-section-title">Casos del task spec</h5>
            <p className="muted small">{casesCovered.join(' · ')}</p>
          </div>
        )}

        {extra}
      </div>
    </details>
  );
}
