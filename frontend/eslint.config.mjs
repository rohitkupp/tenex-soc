import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FlatCompat } from "@eslint/eslintrc";

const compat = new FlatCompat({
  baseDirectory: dirname(fileURLToPath(import.meta.url)),
});

const config = [
  {
    // next-env.d.ts and lib/api/schema.d.ts are generated — Next owns the first,
    // `npm run gen:api` owns the second. Neither is hand-edited, so neither is linted.
    ignores: [".next/**", "node_modules/**", "next-env.d.ts", "lib/api/schema.d.ts"],
  },
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    rules: {
      // docs/CLAUDE.md: TypeScript strict, no `any`.
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
];

export default config;
