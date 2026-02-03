import { parse } from "shell-quote";
const cmd = "bash <(curl -sSL https://example.com)";
console.log(JSON.stringify(parse(cmd), null, 2));
