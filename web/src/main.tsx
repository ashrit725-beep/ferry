import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/fonts.css';
import './styles/tokens.css';
import './styles/base.css';
import './styles/layout.css';
import './styles/components.css';
import { App } from './App.tsx';

const root = document.getElementById('root');
if (!root) throw new Error('The console page has no #root element.');

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
