import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

import { App } from './App';
import { AuthProvider } from './auth/AuthProvider';
import { DialogProvider } from './components/DialogContext';
import './styles.css';

const configuredBase = import.meta.env.BASE_URL.replace(/\/$/, '');
const isStandaloneDevRoot = import.meta.env.DEV && window.location.pathname === '/';
const routerBase = configuredBase === '' || isStandaloneDevRoot ? undefined : configuredBase;

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter basename={routerBase}>
      <AuthProvider>
        <DialogProvider>
          <App />
        </DialogProvider>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
