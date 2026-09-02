const express = require('express');
const app = express();
app.use(express.json());

const mergeRoute = require('./routes/merge');
app.use('/api', mergeRoute);

app.listen(3000, () => console.log('vuln-fixture listening on 3000'));