#!/usr/bin/env node
import { runAgentSshCli } from "../src/cli.js";

runAgentSshCli(process.argv.slice(2)).catch((error) => {
  console.error(error.message);
  process.exit(1);
});
