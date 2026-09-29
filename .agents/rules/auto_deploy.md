# Autonomous Continuous Deployment Rule

**MANDATORY POLICY**:
Every time a production build (`npm run build` or Next.js build) completes successfully:
1. **Do not wait for user confirmation or messages.**
2. Immediately stage and commit all updated project files with a concise, descriptive commit message.
3. Automatically push changes to the remote Git repository: `git push origin main`.
4. Deploy the latest build directly to Vercel (`npx vercel --prod --yes` or ensure production deployment syncs).
5. Ensure this file and any internal development instructions remain excluded from public Vercel deployments via `.vercelignore`.
