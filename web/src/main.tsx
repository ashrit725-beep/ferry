import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { CSPProvider } from '@base-ui/react/csp-provider';
import { MotionConfig } from 'motion/react';
import './index.css';
import { App } from './App.tsx';
import { TooltipProvider } from './components/ui/tooltip.tsx';

const root = document.getElementById('root');
if (!root) throw new Error('The console page has no #root element.');

// CSPProvider: the gateway sends style-src 'self', so Base UI must not inject
// style elements (the one class it needs is in index.css). MotionConfig:
// transform and layout animation stop under prefers-reduced-motion.
createRoot(root).render(
  <StrictMode>
    <CSPProvider disableStyleElements>
      <MotionConfig reducedMotion="user">
        <TooltipProvider delay={500}>
          <App />
        </TooltipProvider>
      </MotionConfig>
    </CSPProvider>
  </StrictMode>,
);
