import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';


const __dirname = path.dirname(fileURLToPath(import.meta.url));

const ai = new GoogleGenAI({ apiKey : process.env.GEMINI_API_KEY});


function cosineSimilarity(a,b){
      let dot = 0;
      let normA = 0;
      let normB = 0;

      for(let i = 0 ; i<a.length;i++){
        dot += a[i] * b[i];
        normA += a[i] * a[i];
        normB += b[i] * b[i];
      }

      return dot/(Math.sqrt(normA) * Math.sqrt(normB));
}

function loadEmbeddings(repoName){
       const embeddingsPath = path.join(__dirname , '..' ,`embeddings-${repoName}.json`);
       if(!fs.existsSync(embeddingsPath)){
          console.warn(`No embeddings found at ${embeddingsPath} — run: node scripts/embedAdvisories.js ${repoName}. Proceeding without retrieved context.`);
           return [];
       }
       return JSON.parse(fs.readFileSync(embeddingsPath , 'utf-8'));
}


export async function retrieveRelevantChunks(repoName , cveId , queryText , topK = 3){
    const allRecords = loadEmbeddings(repoName);
    const recordsForCve = allRecords.filter((record)=> record.cveId  === cveId);

    if(recordsForCve.length === 0){
         return [];
    }

    const response = await ai.models.embedContent({
         model : 'gemini-embedding-001',
         contents : queryText,
         config : { taskType : 'RETRIEVAL_QUERY'},
    });

    const queryEmbedding = response.embeddings[0].values;

    const scored = recordsForCve.map((record)=>({
        chunkText : record.chunkText,
        score : cosineSimilarity(queryEmbedding , record.embedding),
    }));

    scored.sort((a,b) => b.score - a.score);

    return scored.slice(0,topK);
}