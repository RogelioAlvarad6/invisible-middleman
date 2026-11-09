import { defineConfig } from "vite";

// GitHub Pages serves the site from /<repo-name>/, so use relative asset paths.
export default defineConfig({
  base: "./",
});
