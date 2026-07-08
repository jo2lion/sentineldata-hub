import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
// Tailwind v4 entry point -- this file's `@import "tailwindcss";` (plus the
// project's @theme token block, see styles/index.css) is JIT-compiled by the
// @tailwindcss/vite plugin registered in vite.config.ts. A prior pass pointed
// this import at a separate, manually-generated ./styles/output.css instead,
// as a workaround for that plugin having been removed from vite.config.ts's
// plugins array (see that file's own history). output.css was a frozen
// snapshot: it never picked up any utility class added to the app after it
// was generated, and was missing the overwhelming majority of the grid-*/
// signal-* classes App.tsx actually uses. Restoring the plugin (vite.config.ts)
// and pointing this import back at index.css are one fix, done together --
// half of it alone would still leave the app unstyled or frozen.
import './styles/index.css'

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error(
    "Root mount element '#root' was not found in index.html — check the DOM shell before debugging React."
  );
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      staleTime: 15_000,
      refetchOnWindowFocus: false,
    },
  },
});

createRoot(rootElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>
);
