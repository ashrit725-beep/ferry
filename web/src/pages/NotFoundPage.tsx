import { EmptyState } from '../components/console/states.tsx';
import { PageHeader } from '../components/console/page-header.tsx';
import { buttonVariants } from '../components/ui/button.tsx';
import { paths, toHash } from '../router.ts';

export function NotFoundPage({ path }: { path: string }) {
  return (
    <>
      <PageHeader title="Page not found" />
      <div className="rounded-lg bg-panel ring-1 ring-hairline">
        <EmptyState
          title={`There is no console page at #${path}.`}
          action={
            <a className={buttonVariants({ variant: 'outline', size: 'sm' })} href={toHash(paths.overview)}>
              Go to Overview
            </a>
          }
        >
          Links to bundles use the bundle id (<code className="font-mono">sha256:</code> followed by 64 hex digits) or a verification number.
        </EmptyState>
      </div>
    </>
  );
}
