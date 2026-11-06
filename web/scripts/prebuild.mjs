// Empties internal/server/webdist except its .gitignore, which keeps the directory in the
// repository: a build that fails halfway must not leave a tracked file deleted.
import { readdirSync, rmSync } from "node:fs";
const dir = new URL("../../internal/server/webdist/", import.meta.url);
for (const name of readdirSync(dir)) if (name !== ".gitignore") rmSync(new URL(name, dir), { recursive: true, force: true });
