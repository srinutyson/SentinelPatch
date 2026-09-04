import { getDependencies } from './scripts/extractDependencies.js';
 
function summarize(reponame) {
  console.log(`\n=== ${reponame} ===`);
  const result = getDependencies(reponame);
 
  console.log(`Total packages: ${result.length}`);
  console.log(`Direct: ${result.filter(p => p.direct).length}`);
  console.log(`Transitive: ${result.filter(p => !p.direct).length}`);
 
  const nullVersions = result.filter(p => !p.version);
  console.log(`Null versions: ${nullVersions.length}`);
  if (nullVersions.length) console.log('  ->', nullVersions.map(p => p.name));
 
  const scoped = result.filter(p => p.name.startsWith('@'));
  console.log(`Scoped packages found: ${scoped.length}`);
  if (scoped.length) console.log('  ->', scoped.slice(0, 5).map(p => p.name));
 
  const nameCounts = {};
  for (const p of result) nameCounts[p.name] = (nameCounts[p.name] || 0) + 1;
  const dupes = Object.entries(nameCounts).filter(([, c]) => c > 1);
  console.log(`Names appearing more than once: ${dupes.length}`);
  if (dupes.length) {
    for (const [name] of dupes.slice(0, 5)) {
      console.log(`  ${name}:`, result.filter(p => p.name === name));
    }
  }
 
  console.log('Sample (first 5):', JSON.stringify(result.slice(0, 5), null, 2));
}
 
summarize('vuln-fixture');
summarize('hackathon-starter');



