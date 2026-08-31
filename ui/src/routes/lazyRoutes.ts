import { createLazyRoute } from '../lib/routeLoader';

// Central lazy-route registry. Each route shares one cache/pending promise
// between its rendered component and its preload() so a chunk fetched
// during the login loader is reused at mount time instead of re-requested.

const analysisRoute = createLazyRoute(() =>
  import('./analysis/AnalysisPage').then((module) => module.AnalysisPage),
);
const settingsRoute = createLazyRoute(() =>
  import('./settings/SettingsPage').then((module) => module.SettingsPage),
);
const telemetryRoute = createLazyRoute(() =>
  import('./telemetry/TelemetryPage').then((module) => module.TelemetryPage),
);
const endpointsRoute = createLazyRoute(() =>
  import('./EndpointsPage').then((module) => module.EndpointsPage),
);
const overridesRoute = createLazyRoute(() =>
  import('./OverridesPage').then((module) => module.OverridesPage),
);
const userReportsRoute = createLazyRoute(() =>
  import('./UserReportsPage').then((module) => module.UserReportsPage),
);
const systemRoute = createLazyRoute(() =>
  import('./SystemPage').then((module) => module.SystemPage),
);

export const AnalysisPage = analysisRoute.Component;
export const SettingsPage = settingsRoute.Component;
export const TelemetryPage = telemetryRoute.Component;
export const EndpointsPage = endpointsRoute.Component;
export const OverridesPage = overridesRoute.Component;
export const UserReportsPage = userReportsRoute.Component;
export const SystemPage = systemRoute.Component;

// The default landing route after login. Prepared in parallel with the
// auth request so one continuous loader covers login → Analysis.
export const preloadAnalysisRoute = analysisRoute.preload;
