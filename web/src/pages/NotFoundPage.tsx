import { PageHeader } from '../components/Panel.tsx';
import { paths, toHash } from '../router.ts';

export function NotFoundPage({ path }: { path: string }) {
  return (
    <>
      <PageHeader title="Page not found" />
      <div className="panel">
        <div className="state">
          <p className="state__body">
            There is no console page at <code>#{path}</code>. Links to bundles use the bundle id (
            <code>sha256:</code> followed by 64 hex digits) or a verification number.
          </p>
          <a className="button" href={toHash(paths.overview)}>
            Go to Overview
          </a>
        </div>
      </div>
    </>
  );
}
