# Automated Continuous Deployment Workflow

> **Note**: This file is strictly excluded from Vercel deployments via `.vercelignore` to avoid public exposure.

## Workflow Policy
Every time a build completes successfully:
1. **Zero-Wait Auto-Commit**: Automatically stage and commit code without waiting for user confirmation.
2. **Git Push**: Push the commit directly to GitHub (`git push origin main`).
3. **Vercel Deployment**: Automatically execute production deployment to Vercel (`npx vercel --prod --yes`).
4. **Deployment Isolation**: Internal instructions, agent rules, and local logs are strictly filtered out of the deployment artifact bundle.
