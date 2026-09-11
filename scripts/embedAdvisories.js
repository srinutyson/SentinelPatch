import 'dotenv/config';
import fs from 'fs';
import { GoogleGenAI } from '@google/genai';
import { resolveScanContext, ensureOutputDirs } from './projectPaths.js';

let ai = null;
function getAI(){
    if(!ai){
        ai = new GoogleGenAI({ apiKey : process.env.GEMINI_API_KEY});
    }
    return ai;
}

 function chunkText(text , maxChunkLength = 8000){
    const paragraphs = text
             .split(/\n\s*\n/)
             .map((p) => p.trim())
             .filter((p) => p.length > 0);
    const chunks = [];
    for(const paragraph of paragraphs){
        if(paragraph.length <= maxChunkLength){
            chunks.push(paragraph);
        }
        else {
            for(let i = 0; i<paragraph.length ; i += maxChunkLength){
                chunks.push(paragraph.slice(i , i+ maxChunkLength));
            }
        }

    }

    return chunks;

}

async function embedChunks(chunks){
       const response = await getAI().models.embedContent({
           model : 'gemini-embedding-001',
           contents : chunks,
           config : {
               taskType : 'RETRIEVAL_DOCUMENT'
           },
       });

       return response.embeddings.map((embedding) => embedding.values);
}

function loadVulnerabilityReport(ctx) {
    if (!fs.existsSync(ctx.vulnerabilitiesPath)) {
        throw new Error(`No vulnerability report found at ${ctx.vulnerabilitiesPath} — run the vulnerability query step first.`);
    }
    return JSON.parse(fs.readFileSync(ctx.vulnerabilitiesPath, 'utf-8'));
}

export async function embedAdvisoriesForRepo(ctx){
      ensureOutputDirs(ctx);
      const report = loadVulnerabilityReport(ctx);
      const vulnerablePackages = report.filter((entry) => entry.vulnerabilities && entry.vulnerabilities.length > 0);

      const records = [];

      for(const dep of vulnerablePackages){
           for(const vuln of dep.vulnerabilities){
              const chunks = chunkText(vuln.details || vuln.summary || '');
              if(chunks.length === 0) continue;

              console.log(`Embedding ${chunks.length} chunk(s) for ${vuln.id}...`);
              const embeddings = await embedChunks(chunks);

              chunks.forEach((chunk,index)=>{
                   records.push({
                      cveId : vuln.id,
                      chunkIndex : index,
                      chunkText : chunk,
                      embedding : embeddings[index],
                   });
              });
           }
      }

    fs.writeFileSync(ctx.embeddingsPath, JSON.stringify(records, null, 2));
    console.log(`Wrote ${records.length} chunk embedding(s) to ${ctx.embeddingsPath}`);

    return records;
}

if (import.meta.url === `file://${process.argv[1]}`) {
    const repoPathArg = process.argv[2] || 'target-repos/vuln-fixture';
    const ctx = resolveScanContext(repoPathArg);
    await embedAdvisoriesForRepo(ctx);
}
