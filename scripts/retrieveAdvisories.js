import 'dotenv/config';
import fs from 'fs';
import { GoogleGenAI } from '@google/genai';

let ai = null;
function getAI(){
    if(!ai){
        ai = new GoogleGenAI({ apiKey : process.env.GEMINI_API_KEY});
    }
    return ai;
}

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

function loadEmbeddings(ctx){
       if(!fs.existsSync(ctx.embeddingsPath)){
          console.warn(`No embeddings found at ${ctx.embeddingsPath} — run the embedding step first. Proceeding without retrieved context.`);
           return [];
       }
       return JSON.parse(fs.readFileSync(ctx.embeddingsPath , 'utf-8'));
}

export async function retrieveRelevantChunks(ctx , cveId , queryText , topK = 3){
    const allRecords = loadEmbeddings(ctx);
    const recordsForCve = allRecords.filter((record)=> record.cveId  === cveId);

    if(recordsForCve.length === 0){
         return [];
    }

    const response = await getAI().models.embedContent({
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
