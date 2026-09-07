import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const ai = new GoogleGenAI({ apiKey : process.env.GEMINI_API_KEY});

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
       const response = await ai.models.embedContent({
           model : 'gemini-embedding-001',
           contents : chunks,
           config : {
               taskType : 'RETRIEVAL_DOCUMENT'
           },
       });

       return response.embeddings.map((embedding) => embedding.values);
}

function loadVulnerabilityReport(repoName) {
    const reportPath = path.join(__dirname, '..', `vulnerabilities-${repoName}.json`);
    if (!fs.existsSync(reportPath)) {
        throw new Error(`No vulnerability report found at ${reportPath} — run: node scripts/queryVulnerabilities.js ${repoName}`);
    }
    return JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
}

export async function embedAdvisoriesForRepo(repoName){
      const report = loadVulnerabilityReport(repoName);
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

      const outputPath = path.join(__dirname, '..', `embeddings-${repoName}.json`);
    fs.writeFileSync(outputPath, JSON.stringify(records, null, 2));
    console.log(`Wrote ${records.length} chunk embedding(s) to ${outputPath}`);

    return records;
}


const repoName = process.argv[2] || 'vuln-fixture';
embedAdvisoriesForRepo(repoName);