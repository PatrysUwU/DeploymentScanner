import { AstAnalyser } from "@nodesecure/js-x-ray";

const scanner = new AstAnalyser();

const { warnings, dependencies } = await scanner.analyseFile("./src/test.js");

console.log(dependencies);
console.dir(warnings, { depth: null });
