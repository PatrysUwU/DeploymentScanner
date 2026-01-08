import { AstAnalyser } from "@nodesecure/js-x-ray";
import { readFileSync } from "node:fs";

const scanner = new AstAnalyser();

const { warnings, dependencies } = await scanner.analyseFile("./bad.jsx");

console.log(dependencies);
console.dir(warnings, { depth: null });
