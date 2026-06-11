import { JsonView } from './JsonView';
import type { ActionResult } from '../lib/actions';

type Props = {
  title: string;
  result: ActionResult<unknown> | null;
  loading: boolean;
};

export function ResponsePanel({ title, result, loading }: Props) {
  const errorAsObject = isPlainObject(result?.error) ? (result!.error as Record<string, unknown>) : null;
  const errorAsString = typeof result?.error === 'string' ? result.error : null;
  // Prefer `data` when it's a structured body (most common case for aegis-core 4xx/5xx).
  const hasStructuredBody = result?.data !== undefined && result.data !== null && typeof result.data === 'object';

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
