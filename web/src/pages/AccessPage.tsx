import { PageHeader } from '../components/Panel.tsx';
import { Tabs, type TabItem } from '../components/Tabs.tsx';
import { paths, replaceRoute, type AccessTab } from '../router.ts';
import { AppsTab } from './access/AppsTab.tsx';
import { ExplainTab } from './access/ExplainTab.tsx';
import { PolicyTab } from './access/PolicyTab.tsx';

const TABS: readonly TabItem<AccessTab>[] = [
  { id: 'apps', label: 'Apps and keys' },
  { id: 'policy', label: 'Policy' },
  { id: 'explain', label: 'Explain a decision' },
];

/** Access: app identities and their keys, the access policy, and the decision explainer. */
export function AccessPage({ tab }: { tab: AccessTab }) {
  return (
    <>
      <PageHeader
        title="Access"
        description="Apps authenticate with API keys. The active policy decides which app may use which model; anything no rule allows is denied."
      />
      <Tabs
        tabs={TABS}
        selected={tab}
        onSelect={(t) => replaceRoute(paths.access(t))}
        label="Access sections"
        panels={{ apps: <AppsTab />, policy: <PolicyTab />, explain: <ExplainTab /> }}
      />
    </>
  );
}
