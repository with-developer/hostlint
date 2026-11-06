// The build empties internal/server/webdist; its .gitignore keeps the directory in the repository.
import { writeFileSync } from "node:fs";
writeFileSync(new URL("../../internal/server/webdist/.gitignore", import.meta.url), "*\n!.gitignore\n");
