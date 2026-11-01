#!/usr/bin/env node
import { createCli } from '../src/cli/index.js';

const program = createCli();
await program.parseAsync(process.argv);
